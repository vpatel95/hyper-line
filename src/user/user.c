#include "avd_pipe.h"
#include "avd_log.h"
#include "avd_session.h"
#include "avd_message.h"

char                        *g_conf_file_name = NULL;
extern avd_user_session_t   g_user_session;

int32_t send_tasks(user_t *user) {
    int32_t     i, j, rc;
    int32_t     num_tasks = user->num_tasks;
    conn_info_t *conn = &user->conn;

    for (i = 0; i < num_tasks; i++) {
#define task user->tasks[i]

        if (get_task_sent_u_sess(task.name)) {
            continue;
        }

        int32_t     tmsg_sz;
        int32_t     data_sz;
        message_t   msg;
        tmsg_args_t tmsg;

        memset(&msg, 0, sizeof(msg));

        tmsg.task_name = (char *)malloc(strlen(task.name)+1);

        tmsg.num_stages = task.num_stages;
        snprintf(tmsg.task_name, strlen(task.name)+1, "%s", task.name);

        for (j = 0; j < task.num_stages; j++) {
#define stage task.stages[j]
            tmsg.stages[j].num = stage.num;
            tmsg.stages[j].func = (char *)malloc(strlen(stage.func_name)+1);
            snprintf(tmsg.stages[j].func, strlen(stage.func_name)+1, "%s", stage.func_name);
#undef stage
        }

        tmsg_sz = tmsg_args_t_encoded_sz(&tmsg);
        data_sz = tmsg_args_t_encode(msg.buf, 0, tmsg_sz, &tmsg);

        set_msg_type(msg.hdr.type, AVD_MSG_F_TASK);
        msg.hdr.size = MSG_HDR_SZ + data_sz;
        msg.hdr.seq_no = 1;

        rc = send(conn->sockfd, &msg, msg.hdr.size, 0);
        if (rc < 0) {
            avd_log_error("Task send error: %s", strerror(errno));
            goto bail;
        }

        if (0 != (send_file(task.filename, conn->sockfd, AVD_MSG_F_FILE_TSK))) {
            avd_log_error("Failed to send task files to the server");
            goto bail;
        }

        if (0 != (send_file(task.input_file, conn->sockfd, AVD_MSG_F_FILE_IN))) {
            avd_log_error("Failed to send task files to the server");
            goto bail;
        }

        set_task_sent_u_sess(task.name);
#undef task
    }

    return 0;

bail:
    return -1;
}

int32_t user_init () {
    int32_t     conn_fd;

    conn_fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn_fd < 0) {
        avd_log_fatal("Client socket setup failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return conn_fd;
}

void server_communication (user_t *user) {
    int32_t         rc;
    message_t       rmsg;
    conn_info_t     *conn = &user->conn;

    memset(&rmsg, 0, sizeof(rmsg));

#define sockfd conn->sockfd
    if (sockfd < 0)
        return;

    if (0 != (rc = send_tasks(user))) {
        avd_log_error("Error sending tasks to the server");
        // TODO : Handle the error and do not exit
        exit(1);
    }

    while(true) {
        msleep(500);
    }

#undef sockfd
}

int32_t reconnect(user_t *user) {
    int32_t         rc = -1;
    int32_t         umsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &user->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    avd_log_info("Restored user session");

    umsg_rc_t umsg;
    umsg.uid = user->id;
    umsg.uname = (char *)malloc(strlen(user->uname)+1);
    snprintf(umsg.uname, strlen(user->uname)+1, "%s", user->uname);

    umsg_sz = umsg_rc_t_encoded_sz(&umsg);
    data_sz = umsg_rc_t_encode(msg.buf, 0, umsg_sz, &umsg);

    set_msg_type(msg.hdr.type, AVD_MSG_F_RE_CON);
    msg.hdr.size = MSG_HDR_SZ + data_sz;

    if(0 > (rc = send(conn->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_RE_CON)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }
        } else {
            avd_log_error("Expecting message type %d, received %d",
                           AVD_MSG_F_RE_CON, rmsg.hdr.type);
            goto bail;
        }
    }

    smsg_urc_t m;
    smsg_urc_t_decode(rmsg.buf, 0, sizeof(rmsg.buf), &m);

    user->id = m.uid;
    user->poll_id = m.poll_id;

    update_user_u_sess("id", cJSON_CreateNumber(user->id));
    update_user_u_sess("poll_id", cJSON_CreateNumber(user->poll_id));

    return 0;

bail:
    close_fd(conn->sockfd);
    return rc;
}

int32_t new_connection(user_t *user) {
    int32_t         rc = -1;
    int32_t         umsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &user->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_msg_type(msg.hdr.type, AVD_MSG_F_NEW_CON);
    avd_log_info("User session not found. Creating new connection");

    umsg_nc_t   umsg;
    umsg.uname = (char *)malloc(strlen(user->uname)+1);
    snprintf(umsg.uname, strlen(user->uname)+1, "%s", user->uname);

    umsg_sz = umsg_nc_t_encoded_sz(&umsg);
    data_sz = umsg_nc_t_encode(msg.buf, 0, umsg_sz, &umsg);
    msg.hdr.size = MSG_HDR_SZ + data_sz;

    rc = send(conn->sockfd, &msg, msg.hdr.size, 0);
    if (rc < 0) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_NEW_CON)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }
        } else {
            avd_log_error("Expecting message type %d, received %d",
                           AVD_MSG_F_NEW_CON, rmsg.hdr.type);
            goto bail;
        }
    }

    smsg_urc_t m;
    smsg_urc_t_decode(rmsg.buf, 0, sizeof(rmsg.buf), &m);

    user->id = m.uid;
    user->poll_id = m.poll_id;

    create_user_u_sess(user);

    return 0;
bail:
    close_fd(conn->sockfd);
    return rc;
}

int32_t connect_server(user_t *user) {

    int32_t             rc = -1;
    conn_info_t         *conn = &user->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = user_init();

    if (0 == (rc = inet_pton(AF_INET, conn->addr, &srvr_addr.sin_addr.s_addr))) {
        avd_log_error("Server IP inet_pton error:%s", strerror(errno));
        goto bail;
    }
    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    avd_log_debug("Connecting to server on %s:%d", conn->addr, conn->port);
    if (0 > (rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr)))) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s",
                conn->addr, conn->port, strerror(errno));
        goto bail;
    }

    avd_log_info("Connected to server on %s", sock_ntop(&srvr_addr));

    if (0 != (rc = check_and_get_u_sess(user))) {
        new_connection(user);
    } else {
        reconnect(user);
    }

    return 0;

bail:
    close_fd(conn->sockfd);
    return rc;
}

int32_t start_user (user_t *user) {
    int32_t         rc = -1;

    rc = connect_server(user);
    if (rc < 0) {
        avd_log_error("Cannot establish connection with server: %s\n.", strerror(errno));
        goto bail;
    }

    server_communication(user);
bail:
    return rc;
}

void setup_logger(log_info_t *logger) {
    set_log_file(logger->log_file);
    set_log_level(logger->level);
    set_log_quiet(logger->quiet);
}

int32_t main (int32_t argc, char *argv[]) {

    user_t              user;
    memset(&user, 0, sizeof(user));

    signal_intr(SIGINT, sig_int_handler);

    g_conf_file_name = (char *)argv[1];

    if (argc < 2)
        exit(EXIT_FAILURE);

    if (0 != process_config_file(g_conf_file_name, USER, &user)) {
        avd_log_fatal("Failed to parse config file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    setup_logger(&user.logger);

    start_user(&user);
    return EXIT_SUCCESS;
}
