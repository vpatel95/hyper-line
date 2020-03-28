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

typedef struct avd_stage_session_s {
    cJSON   *root;
} avd_stage_session_t;

typedef struct avd_task_session_s {
    int32_t                 num_stages;
    cJSON                   *root;
    avd_stage_session_t     stg_sess[MAX_STAGES];
} avd_task_session_t;

typedef struct avd_user_session_s {
    int32_t             num_tasks;
    cJSON               *root;
    avd_task_session_t  tsess[MAX_TASK];
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

/*   Common Session Helpers   */
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
    int32_t     i, j, k, rc = -1;
    int32_t     uobj_sz;
    int32_t     wobj_sz;
    avd_server_session_t    *sess = (avd_server_session_t *) &g_srvr_session;

    if (file_exists(SESSION_FILE, F_OK)) {
        if (NULL == (sess->root = parse_json(SESSION_FILE))) {
            goto bail;
        }
    } else {
        sess->root = cJSON_CreateObject();
        if (!sess->root) goto bail;

        cJSON *u_arr = cJSON_CreateArray();
        if (!u_arr) goto bail;

        cJSON_AddItemToObject(sess->root, "users", u_arr);

        cJSON *w_arr = cJSON_CreateArray();
        if (!w_arr) goto bail;

        cJSON_AddItemToObject(sess->root, "workers", w_arr);

        if (0 != write_to_sess_file(sess->root)) {
            goto bail;
        }

        return 0;
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
                avd_task_session_t  *tsess = &usess->tsess[j];
                tsess->root = cJSON_GetArrayItem(task_arr, j);

                cJSON *stg_arr = cJSON_GetObjectItem(tsess->root, "stages");
                tsess->num_stages = cJSON_GetArraySize(stg_arr);
                for (k = 0; k < tsess->num_stages; k++) {
                    avd_stage_session_t *stg_sess = &tsess->stg_sess[k];
                    stg_sess->root = cJSON_GetArrayItem(stg_arr, k);
                }
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

/* SERVER : User Session Helpers */
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

bool user_exists_s_sess(char *uname) {
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

        cJSON *v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
            return true;
        }
    }

bail:
    return false;
}

int32_t add_user_s_sess(server_t *srvr, user_t *u, char *uname) {
    int32_t                 rc = -1;
    cJSON                   *u_arr = NULL;
    cJSON                   *user = NULL;
    cJSON                   *u_id = NULL;
    cJSON                   *u_name = NULL;
    cJSON                   *num_tasks = NULL;
    cJSON                   *num_unassigned = NULL;
    cJSON                   *tasks = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("failed to build server session");
            goto bail;
        }
    }

    u_arr = cJSON_GetObjectItem(sess->root, "users");

    user = cJSON_CreateObject();
    if (!user) goto bail;

    u_id = cJSON_CreateNumber(srvr->new_client_id);
    if (!u_id) goto bail;

    u_name = cJSON_CreateString(uname);
    if (!u_name) goto bail;

    num_tasks = cJSON_CreateNumber(u->num_tasks);
    if (!num_tasks) goto bail;

    num_unassigned = cJSON_CreateNumber(0);
    if (!num_unassigned) goto bail;

    tasks = cJSON_CreateArray();
    if (!tasks) goto bail;

    cJSON_AddItemToObject(user, "id", u_id);
    cJSON_AddItemToObject(user, "uname", u_name);
    cJSON_AddItemToObject(user, "num_tasks", num_tasks);
    cJSON_AddItemToObject(user, "unassigned_workers", num_unassigned);
    cJSON_AddItemToObject(user, "tasks", tasks);
    cJSON_AddItemToArray(u_arr, user);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    build_server_sess();

    u->id = srvr->new_client_id++;

    rc = 0;

bail:
    return rc;
}

bool task_exists_s_sess (char *uname, char *name) {
    int32_t                 i, j;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (uname == NULL || name == NULL) {
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

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
            for (j = 0; j < usess->num_tasks; j++) {
#define task usess->tsess[j]

                v = cJSON_GetObjectItem(task.root, "name");
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

int32_t add_user_task_s_sess(char *uname, cJSON *task) {
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

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
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

int32_t get_user_task_num_s_sess(char *uname) {
    int32_t                 i;
    int32_t                 num = 0;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
            v = cJSON_GetObjectItem(usess->root, "num_tasks");
            if ((!v) || (!v->valueint)) {
                avd_log_debug("cannot extract 'num_tasks' from user object");
                goto bail;
            }

            return v->valueint;
        }
    }

bail:
    return num;
}

int32_t get_user_unassigned_worker_num_s_sess(char *uname) {
    int32_t                 i;
    int32_t                 num = 0;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
            v = cJSON_GetObjectItem(usess->root, "unassigned_workers");
            if ((!v) || (!v->valueint)) {
                avd_log_debug("cannot extract 'unassigned_workers' from user object");
                goto bail;
            }

            return v->valueint;
        }
    }

bail:
    return num;
}

int32_t get_task_unassigned_stage_num_s_sess(char *uname, int32_t tidx) {
    int32_t                 i;
    int32_t                 num = 0;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {

            if (tidx >= usess->num_tasks) {
                goto bail;
            }

#define task usess->tsess[tidx]
            cJSON *val = cJSON_GetObjectItem(task.root, "unassigned_stages");
            if (!val) {
                avd_log_error("Malformed task in session file");
                goto bail;
            }

            return val->valueint;
#undef task
        }
    }

bail:
    return num;
}

cJSON * get_task_field_by_idx_s_sess(char *uname, int32_t tidx, char *field) {
    int32_t                 i;
    cJSON                   *v = NULL;
    cJSON                   *obj = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {

            if (tidx >= usess->num_tasks) {
                goto bail;
            }

#define task usess->tsess[tidx]
            obj = cJSON_GetObjectItem(task.root, field);
            if (!obj) {
                avd_log_error("Malformed task in session file");
                goto bail;
            }
            break;
#undef task
        }
    }

bail:
    return obj;
}

int32_t update_task_field_by_idx_s_sess(char *uname, int32_t tidx, char *field, cJSON *val) {
    int32_t                 i, rc = -1;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {

            if (tidx >= usess->num_tasks) {
                goto bail;
            }

#define task usess->tsess[tidx]
            cJSON_ReplaceItemInObject(task.root, field, val);
            return 0;
#undef task
        }
    }

bail:
    return rc;
}

int32_t update_stage_field_by_idx_s_sess(char *uname, int32_t tidx, int32_t sidx, char *field, cJSON *val) {
    int32_t                 i, rc = -1;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {

            if (tidx >= usess->num_tasks) {
                goto bail;
            }

#define task usess->tsess[tidx]
#define stage task.stg_sess[sidx]
            cJSON_ReplaceItemInObject(stage.root, field, val);
            return 0;
#undef stage
#undef task
        }
    }

bail:
    return rc;
}

cJSON * get_user_field_s_sess(char *uname, char *field) {
    int32_t                 i;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(uname, v->valuestring)) {
            return cJSON_GetObjectItem(usess->root, field);
        }
    }

bail:
    return NULL;
}

int32_t update_user_s_sess(char *uname, char *field, cJSON *value) {
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

        v = cJSON_GetObjectItem(usess->root, "uname");
        if ((!v)) {
            avd_log_debug("cannot extract 'uname' from user object");
            goto bail;
        }

        if (0 == strcmp(uname, v->valuestring)) {
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

int32_t remove_user_s_sess(char *uname) {
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

        cJSON *v = cJSON_GetObjectItem(uobj, "uname");
        if ((!v) || (!v->valuestring)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (0 == strcmp(v->valuestring, uname)) {
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

/* SERVER : Worker Session Helpers */
int32_t get_max_worker_id_s_sess() {
    int max_id = 1;
    int32_t                 i;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_workers; i++) {
        avd_worker_session_t  *wsess = &sess->wsess[i];

        cJSON *v = cJSON_GetObjectItem(wsess->root, "id");
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

bool worker_exists_s_sess(int32_t wid) {
    int32_t                 i;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_workers; i++) {
        avd_worker_session_t  *wsess = &sess->wsess[i];

        cJSON *v = cJSON_GetObjectItem(wsess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from worker object");
            goto bail;
        }

        if (v->valueint == wid) {
            return true;
            break;
        }
    }

bail:
    return false;
}

int32_t add_worker_s_sess (server_t *srvr, worker_t *wrkr, char *uname) {
    int32_t                 rc = -1;
    cJSON                   *w_arr = NULL;
    cJSON                   *w = NULL;
    cJSON                   *w_id = NULL;
    cJSON                   *w_uname = NULL;
    cJSON                   *assigned = NULL;
    cJSON                   *task = NULL;
    cJSON                   *sub_task = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("failed to build server session");
            goto bail;
        }
    }

    w_arr = cJSON_GetObjectItem(sess->root, "workers");

    w = cJSON_CreateObject();
    if (!w) goto bail;

    w_id = cJSON_CreateNumber(srvr->new_client_id);
    if (!w_id) goto bail;

    w_uname = cJSON_CreateString(uname);
    if (!w_uname) goto bail;

    assigned = cJSON_CreateFalse();
    if (!assigned) goto bail;

    task = cJSON_CreateObject();
    if (!task) goto bail;

    cJSON_AddItemToObject(w, "id", w_id);
    cJSON_AddItemToObject(w, "uname", w_uname);
    cJSON_AddItemToObject(w, "assigned", assigned);
    cJSON_AddItemToObject(w, "task", task);
    cJSON_AddItemToObject(w, "sub_task_id", sub_task);
    cJSON_AddItemToArray(w_arr, w);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    cJSON *v = get_user_field_s_sess(uname, "unassigned_workers");
    update_user_s_sess(uname, "unassigned_workers", cJSON_CreateNumber(v->valueint+1));

    build_server_sess();

    wrkr->id = srvr->new_client_id++;

    rc = 0;

bail:
    return rc;
}

int32_t remove_worker_s_sess(int32_t wid) {
    int32_t                 i, rc = -1;
    int32_t                 wobj_sz;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    cJSON   *wobj_arr = cJSON_GetObjectItem(sess->root, "workers");
    if (!wobj_arr) {
        avd_log_debug("Failed to parse 'workers' field from session file");
        goto bail;
    }

    wobj_sz = cJSON_GetArraySize(wobj_arr);
    for (i = 0; i < wobj_sz; i++) {
        cJSON *wobj = cJSON_GetArrayItem(wobj_arr, i);
        if (!wobj) {
            avd_log_debug("Failed to retrieve user from 'workers' object");
            goto bail;
        }

        cJSON *v = cJSON_GetObjectItem(wobj, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == wid) {
            cJSON_DeleteItemFromArray(wobj_arr, i);

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

int32_t update_worker_s_sess(int32_t wid, char *field, cJSON *value) {
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

    for (i = 0; i < sess->num_workers; i++) {
        avd_worker_session_t  *wsess = &sess->wsess[i];

        v = cJSON_GetObjectItem(wsess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from worker object");
            goto bail;
        }

        if (wid == v->valueint) {
            cJSON_ReplaceItemInObject(wsess->root, field, value);

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

/* USER Session Helpers */
int32_t create_user_u_sess(user_t *user) {
    int32_t                 i, rc = -1;
    cJSON                   *u_id = NULL;
    cJSON                   *u_name = NULL;
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

        u_name = cJSON_CreateString(user->uname);
        if (!u_name) goto bail;

        poll_id = cJSON_CreateNumber(user->poll_id);
        if (!poll_id) goto bail;

        task_arr = cJSON_CreateArray();
        if(!task_arr) goto bail;

        for (i = 0; i < user->num_tasks; i++) {
            cJSON *task = cJSON_CreateObject();

            cJSON_AddItemToObject(task, "name", cJSON_CreateString(user->tasks[i].name));
            cJSON_AddItemToObject(task, "sent", cJSON_CreateFalse());

            cJSON_AddItemToArray(task_arr, task);
        }

        cJSON_AddItemToObject(sess->root, "id", u_id);
        cJSON_AddItemToObject(sess->root, "uname", u_name);
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

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            return 0;

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

    v = cJSON_GetObjectItem(sess->root, "uname");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'uname' in session file");
        goto bail;
    }
    snprintf(user->uname, strlen(v->valuestring)+1, "%s", v->valuestring);

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

int32_t check_and_get_u_sess(user_t *user) {
    int32_t     rc = -1;
    if (file_exists(SESSION_FILE, F_OK)) {
        if (0 != (rc = get_user_u_sess(user))) {
            avd_log_fatal("Failed to restore user session");
            exit(EXIT_FAILURE);
        }
        rc = 0;
    }

    return rc;
}

int32_t update_user_u_sess(char *field, cJSON *value) {
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

/* WORKER Session Helpers */
int32_t get_worker_w_sess(worker_t *wrkr) {
    cJSON                   *v = NULL;
    int32_t                 rc = -1;
    avd_worker_session_t    *sess = (avd_worker_session_t *)&g_wrkr_session;

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
    wrkr->id = v->valueint;

    v = cJSON_GetObjectItem(sess->root, "poll_id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'poll_id' in session file");
        goto bail;
    }
    wrkr->poll_id = v->valueint;

    rc = 0;

bail:
    return rc;
}

int32_t check_and_get_w_sess(worker_t *wrkr) {
    int32_t     rc = -1;
    if (file_exists(SESSION_FILE, F_OK)) {
        if (0 != (rc = get_worker_w_sess(wrkr))) {
            avd_log_fatal("Failed to restore user session");
            exit(EXIT_FAILURE);
        }
        rc = 0;
    }

    return rc;
}

int32_t create_worker_w_sess(worker_t *worker) {
    int32_t                 rc = -1;
    cJSON                   *w_id = NULL;
    cJSON                   *poll_id = NULL;
    avd_worker_session_t    *sess = (avd_worker_session_t *)&g_wrkr_session;

    if (file_exists(SESSION_FILE, F_OK)) {
        sess->root = parse_json(SESSION_FILE);
    } else {
        sess->root = cJSON_CreateObject();
        if (!sess->root) goto bail;

        w_id = cJSON_CreateNumber(worker->id);
        if (!w_id) goto bail;

        poll_id = cJSON_CreateNumber(worker->poll_id);
        if (!poll_id) goto bail;

        cJSON *task = cJSON_CreateObject();

        cJSON_AddItemToObject(task, "name", cJSON_CreateString(worker->tname));
        cJSON_AddItemToObject(task, "rcvd", cJSON_CreateFalse());

        cJSON_AddItemToObject(sess->root, "id", w_id);
        cJSON_AddItemToObject(sess->root, "poll_id", poll_id);
        cJSON_AddItemToObject(sess->root, "task", task);
    }

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    rc = 0;

bail:
    return rc;
}

int32_t update_worker_w_sess(char *field, cJSON *value) {
    int32_t                 rc = -1;
    avd_worker_session_t    *sess = (avd_worker_session_t *)&g_wrkr_session;

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
