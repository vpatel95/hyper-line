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

        cJSON *update_id = cJSON_CreateNumber(0);
        if (!update_id) goto bail;

        cJSON_AddItemToObject(sess->root, "update_id", update_id);

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

void increment_update_id(cJSON *root) {
    cJSON *v = NULL;

    v = cJSON_GetObjectItem(root, "update_id");
    if (!v) {
        avd_log_error("Cannot increment the update_id in the server config");
        return;
    }

    cJSON_ReplaceItemInObject(root, "update_id", cJSON_CreateNumber(v->valueint + 1));

    if (0 != write_to_sess_file(root)) {
        return;
    }

    build_server_sess();

    return;
}

/* SERVER : User Session Helpers */
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

    increment_update_id(sess->root);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    build_server_sess();

    u->id = srvr->new_client_id++;

    rc = 0;

bail:
    return rc;
}

int32_t add_task_s_sess(char *uname, cJSON *task) {
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

            increment_update_id(sess->root);

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
            if (!v) {
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

cJSON * get_task_field_by_id_s_sess (char *uname, int32_t tid, char *field) {
    int32_t                 i, j;
    cJSON                   *v = NULL;
    cJSON                   *obj = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (uname == NULL || field == NULL) {
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

                v = cJSON_GetObjectItem(task.root, "id");
                if ((!v) || (!v->valueint)) {
                    avd_log_error("Malformed task in session file");
                    goto bail;
                }

                if (tid == v->valueint) {
                    obj = cJSON_GetObjectItem(task.root, field);
                    if (!obj) {
                        avd_log_error("Cannot find field '%s' in task session", field);
                        goto bail;
                    }
                    return obj;
                }
#undef task
            }
        }
    }

bail:
    return NULL;
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

cJSON * get_worker_peer(char *uname, int32_t tid, int32_t snum) {
    int32_t                 i;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed tp build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_workers; i++) {
        avd_worker_session_t    *wsess = &sess->wsess[i];

        v = cJSON_GetObjectItem(wsess->root, "uname");

        if (0 != strcmp(uname, v->valuestring)) {
            continue;
        }

        cJSON *task = cJSON_GetObjectItem(wsess->root, "task");
        if (!task) goto bail;

        v = cJSON_GetObjectItem(task, "id");

        if (tid == v->valueint) {

            cJSON *num = cJSON_GetObjectItem(task, "stg_num");
            if (!num) goto bail;

            if ((snum - 1) == num->valueint) {
                cJSON *peer = cJSON_GetObjectItem(wsess->root, "peer");
                return peer;
            }
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

            increment_update_id(sess->root);

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

            increment_update_id(sess->root);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            build_server_sess();

            return 0;
#undef task
        }
    }

bail:
    return rc;
}

cJSON * get_stage_field_by_id_s_sess (char *uname, int32_t tid, int32_t snum, char *field) {
    int32_t                 i, j, k;
    cJSON                   *v = NULL;
    cJSON                   *obj = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (uname == NULL || field == NULL) {
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

                v = cJSON_GetObjectItem(task.root, "id");
                if ((!v) || (!v->valueint)) {
                    avd_log_error("Malformed task in session file");
                    goto bail;
                }

                if (tid == v->valueint) {
                    for (k = 0; k < task.num_stages; k++) {
#define stage task.stg_sess[k]
                        v = cJSON_GetObjectItem(stage.root, "num");
                        if ((!v) || (!v->valueint)) {
                            avd_log_error("Malformed task in session file");
                            goto bail;
                        }

                        if (snum == v->valueint) {
                            obj = cJSON_GetObjectItem(stage.root, field);
                            if (!obj) {
                                avd_log_error("Cannot find field '%s' in stage session", field);
                                goto bail;
                            }
                            return obj;
                        }
#undef stage
                    }
                }
#undef task
            }
        }
    }

bail:
    return NULL;
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

            increment_update_id(sess->root);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            build_server_sess();

            return 0;
#undef stage
#undef task
        }
    }

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

            increment_update_id(sess->root);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            build_server_sess();

            break;
        }
    }

    build_server_sess();
    rc = 0;
bail:
    return rc;
}

/* SERVER : Worker Session Helpers */
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

int32_t add_worker_s_sess (server_t *srvr, worker_t *w, char *uname) {
    int32_t                 rc = -1;
    cJSON                   *w_arr = NULL;
    cJSON                   *wrkr = NULL;
    cJSON                   *w_id = NULL;
    cJSON                   *w_uname = NULL;
    cJSON                   *assigned = NULL;
    cJSON                   *peer = NULL;
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

    wrkr = cJSON_CreateObject();
    if (!wrkr) goto bail;

    w_id = cJSON_CreateNumber(srvr->new_client_id);
    if (!w_id) goto bail;

    w_uname = cJSON_CreateString(uname);
    if (!w_uname) goto bail;

    assigned = cJSON_CreateFalse();
    if (!assigned) goto bail;

    task = cJSON_CreateObject();
    if (!task) goto bail;

    peer = cJSON_CreateObject();
    if (!peer) goto bail;

    cJSON_AddItemToObject(peer, "id", cJSON_CreateNumber(w_id->valueint));
    cJSON_AddItemToObject(peer, "addr", cJSON_CreateString(w->ps.addr));
    cJSON_AddItemToObject(peer, "port", cJSON_CreateNumber(w->ps.port));

    cJSON_AddItemToObject(wrkr, "id", w_id);
    cJSON_AddItemToObject(wrkr, "uname", w_uname);
    cJSON_AddItemToObject(wrkr, "assigned", assigned);
    cJSON_AddItemToObject(wrkr, "task", task);
    cJSON_AddItemToObject(wrkr, "peer", peer);
    cJSON_AddItemToObject(wrkr, "sub_task_id", sub_task);
    cJSON_AddItemToArray(w_arr, wrkr);

    cJSON *v = get_user_field_s_sess(uname, "unassigned_workers");
    update_user_s_sess(uname, "unassigned_workers", cJSON_CreateNumber(v->valueint+1));

    increment_update_id(sess->root);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    build_server_sess();

    w->id = srvr->new_client_id++;

    rc = 0;

bail:
    return rc;
}

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

            increment_update_id(sess->root);

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

            increment_update_id(sess->root);

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
int32_t get_worker_w_sess(worker_t *w) {
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
    w->id = v->valueint;

    v = cJSON_GetObjectItem(sess->root, "poll_id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'poll_id' in session file");
        goto bail;
    }
    w->poll_id = v->valueint;

    w->peer_id = cJSON_IsTrue(cJSON_GetObjectItem(sess->root, "peer_id"));

    cJSON *tobj = cJSON_GetObjectItem(sess->root, "task");
    if (!tobj) goto bail;

    v = cJSON_GetObjectItem(tobj, "id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find task id in session");
        goto bail;
    }
    w->tid = v->valueint;

    v = cJSON_GetObjectItem(tobj, "num");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find task num in session");
        goto bail;
    }
    w->stg_num = v->valueint;

    v = cJSON_GetObjectItem(tobj, "func");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find task func in session");
        goto bail;
    }
    w->func = (char *)malloc(strlen(v->valuestring)+1);
    snprintf(w->func, strlen(v->valuestring)+1, "%s", v->valuestring);

    cJSON *pobj = cJSON_GetObjectItem(sess->root, "peer_server");
    if (!pobj) goto bail;

    v = cJSON_GetObjectItem(pobj, "pid");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find task id in session");
        goto bail;
    }
    w->ps_id = v->valueint;

    v = cJSON_GetObjectItem(pobj, "port");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find task num in session");
        goto bail;
    }
    w->ps.port = v->valueint;

    v = cJSON_GetObjectItem(pobj, "addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find task func in session");
        goto bail;
    }
    w->ps.addr = (char *)malloc(strlen(v->valuestring)+1);
    snprintf(w->ps.addr, strlen(v->valuestring)+1, "%s", v->valuestring);

    rc = 0;

bail:
    return rc;
}

int32_t check_and_get_w_sess(worker_t *w) {
    int32_t     rc = -1;
    if (file_exists(SESSION_FILE, F_OK)) {
        if (0 != (rc = get_worker_w_sess(w))) {
            avd_log_fatal("Failed to restore worker session");
            exit(EXIT_FAILURE);
        }
        rc = 0;
    }

    return rc;
}

int32_t create_worker_w_sess(worker_t *w) {
    int32_t                 rc = -1;
    cJSON                   *v = NULL;
    avd_worker_session_t    *sess = (avd_worker_session_t *)&g_wrkr_session;

    if (file_exists(SESSION_FILE, F_OK)) {
        sess->root = parse_json(SESSION_FILE);
    } else {
        sess->root = cJSON_CreateObject();
        if (!sess->root) goto bail;

        v = cJSON_CreateNumber(w->id);
        if (!v) goto bail;
        cJSON_AddItemToObject(sess->root, "id", v);

        v = cJSON_CreateNumber(w->poll_id);
        if (!v) goto bail;
        cJSON_AddItemToObject(sess->root, "poll_id", v);

        v = cJSON_CreateObject();
        cJSON_AddItemToObject(sess->root, "task", v);

        v = cJSON_CreateObject();
        cJSON_AddItemToObject(sess->root, "peer_server", v);

        v = cJSON_CreateString(w->bin_file);
        cJSON_AddItemToObject(sess->root, "task_file", v);

        v = cJSON_CreateString(w->input_file);
        cJSON_AddItemToObject(sess->root, "input_file", v);

        v = cJSON_CreateString(w->output_file);
        cJSON_AddItemToObject(sess->root, "output_file", v);

        cJSON_AddItemToObject(sess->root, "update_id", cJSON_CreateNumber(0));
        cJSON_AddItemToObject(sess->root, "type", cJSON_CreateNumber(0));
        cJSON_AddItemToObject(sess->root, "peer_id", cJSON_CreateFalse());
        cJSON_AddItemToObject(sess->root, "task_rcvd", cJSON_CreateFalse());
        cJSON_AddItemToObject(sess->root, "output_ready", cJSON_CreateFalse());
        cJSON_AddItemToObject(sess->root, "output_sent", cJSON_CreateFalse());
        cJSON_AddItemToObject(sess->root, "input_recv", cJSON_CreateFalse());
        cJSON_AddItemToObject(sess->root, "get_input", cJSON_CreateTrue());
        cJSON_AddItemToObject(sess->root, "task_fin", cJSON_CreateFalse());
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

    increment_update_id(sess->root);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    rc = 0;

bail:
    return rc;
}

/* WORKER: Peer Session Helpers */
bool is_peer_id_w_sess() {
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

    return cJSON_IsTrue(cJSON_GetObjectItem(sess->root, "peer_id"));

bail:
    return false;
}

int32_t get_worker_id_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "id");
    if ((!v) || (!v->valueint)) {
        goto bail;
    }

    return v->valueint;

bail:
    return -1;
}

int32_t get_worker_type_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "type");
    if ((!v) || (!v->valueint)) {
        goto bail;
    }

    return v->valueint;

bail:
    return -1;
}

char * get_worker_task_file_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "task_file");
    if ((!v) || (!v->valuestring)) {
        goto bail;
    }

    return v->valuestring;

bail:
    return NULL;
}

char * get_worker_in_file_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "input_file");
    if ((!v) || (!v->valuestring)) {
        goto bail;
    }

    return v->valuestring;

bail:
    return NULL;
}

char * get_worker_out_file_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "output_file");
    if ((!v) || (!v->valuestring)) {
        goto bail;
    }

    return v->valuestring;

bail:
    return NULL;
}

cJSON * get_worker_task_w_sess() {
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

    cJSON *v = cJSON_GetObjectItem(sess->root, "task");
    if (!v) {
        goto bail;
    }

    return v;

bail:
    return NULL;
}

cJSON * get_peer_server_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "peer_server");
    if (!obj) {
        goto bail;
    }

    return obj;

bail:
    return NULL;
}

bool worker_output_ready_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "output_ready");
    if (!obj) {
        goto bail;
    }

    return cJSON_IsTrue(obj);

bail:
    return false;
}

bool worker_output_sent_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "output_sent");
    if (!obj) {
        goto bail;
    }

    return cJSON_IsTrue(obj);

bail:
    return false;
}

bool worker_input_recv_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "input_recv");
    if (!obj) {
        goto bail;
    }

    return cJSON_IsTrue(obj);

bail:
    return false;
}

bool worker_get_input_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "get_input");
    if (!obj) {
        goto bail;
    }

    return cJSON_IsTrue(obj);

bail:
    return false;
}

bool worker_task_fin_w_sess() {
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

    cJSON *obj = cJSON_GetObjectItem(sess->root, "task_fin");
    if (!obj) {
        goto bail;
    }

    return cJSON_IsTrue(obj);

bail:
    return false;
}
#endif
