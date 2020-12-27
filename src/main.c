/*
SPDX-License-Identifier: MIT
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <regex.h>

#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/prctl.h>

#include <zmq.h>
#include <msgpack.h>
#include <libipset/ipset.h> /* !! version >=7 */

#define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define LINE_SIZE 64
#define V_DELTA_SIZE 16
#define V_IP_SIZE 39
#define TOPIC_SIZE 32

/*
struct app_config {
    int wd_interval;
    bool debug;
};

struct app_config app_config = {
    .wd_interval = 0,
    .debug = false,
};
*/

bool request_terminate = false;
bool request_reload = false;
regex_t ipv4_regex;
regex_t ipv6_regex;
struct ipset *ipset = NULL;

/* signal SIGTERM/SIGINT received, stop main loop */
void signal_handler(int signum)
{
    switch (signum) {
        case SIGINT:
        case SIGTERM:
            fprintf(stderr, "Received request to terminate...\n");
            request_terminate = true;
            break;

        case SIGUSR1:
            fprintf(stderr, "Received request to reload...\n");
            request_reload = true;
            break;
    }
}

void process_list(const void *data, size_t data_size)
{
    msgpack_unpacked unpacked;

    msgpack_unpacked_init(&unpacked);
    if (msgpack_unpack_next(&unpacked, data, data_size, NULL) == MSGPACK_UNPACK_SUCCESS) {
        do {
            if (unpacked.data.type != MSGPACK_OBJECT_MAP) {
                fprintf(stderr, "<3>Received message is not a map\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            msgpack_object_kv *p_list = NULL;

            for (unsigned int i = 0; i != unpacked.data.via.map.size; ++i) {
                msgpack_object_kv *a = unpacked.data.via.map.ptr + i;

                if (strncmp("list", a->key.via.str.ptr, a->key.via.str.size) == 0) {
                    p_list = a;
                    continue;
                }
            }

            if (p_list == NULL) {
                fprintf(stderr, "<3>Received message does not contain all elements\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            if (p_list->val.type != MSGPACK_OBJECT_ARRAY) {
                fprintf(stderr, "<3>Received message does not contain right data types\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            fprintf(stdout, "<7>Start update in transaction\n");
            struct ipset_session *session = ipset_session(ipset);

            fprintf(stdout, "<7>Create dynfw4_tmp list\n");
            ipset_parse_line(ipset, "create dynfw4_tmp hash:ip -exist");
            for (unsigned int j = 0; j != p_list->val.via.array.size; ++j) {
                msgpack_object *p_ip = p_list->val.via.array.ptr + j;

                char v_ip[V_IP_SIZE] = { 0 };
                memset(v_ip, 0, V_IP_SIZE);
                strncpy(v_ip, p_ip->via.str.ptr, min(p_ip->via.str.size, V_IP_SIZE - 1));

                if (regexec(&ipv4_regex, v_ip, 0, NULL, 0) != 0) {
                    fprintf(stderr, "<3>Received message does not contain IPv4, got '%s'\n", v_ip);
                    continue;
                }

                fprintf(stdout, "<7>Add %s\n", v_ip);
                char line[LINE_SIZE] = { 0 };
                memset(line, 0, LINE_SIZE);
                snprintf(line, LINE_SIZE, "add dynfw4_tmp %s -exist", v_ip);
                ipset_parse_line(ipset, line);
            }
            fprintf(stdout, "<7>Swap content of dynfw4_tmp and dynfw4 lists\n");
            ipset_parse_line(ipset, "swap dynfw4_tmp dynfw4");
            fprintf(stdout, "<7>Destroy dynfw4_tmp\n");
            ipset_parse_line(ipset, "destroy dynfw4_tmp");
            fprintf(stdout, "<7>Commit transaction\n");
            ipset_commit(session);
        } while (false);
    }
    msgpack_unpacked_destroy(&unpacked);
}

void process_delta(const void *data, size_t data_size)
{
    msgpack_unpacked unpacked;

    msgpack_unpacked_init(&unpacked);
    if (msgpack_unpack_next(&unpacked, data, data_size, NULL) == MSGPACK_UNPACK_SUCCESS) {
        do {
            if (unpacked.data.type != MSGPACK_OBJECT_MAP) {
                fprintf(stderr, "<3>Received message is not a map\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            msgpack_object_kv *p_delta = NULL;
            msgpack_object_kv *p_ip = NULL;

            for (int i = 0; i != unpacked.data.via.map.size; ++i) {
                msgpack_object_kv *a = unpacked.data.via.map.ptr + i;

                if (strncmp("delta", a->key.via.str.ptr, a->key.via.str.size) == 0) {
                    p_delta = a;
                    continue;
                }
                if (strncmp("ip", a->key.via.str.ptr, a->key.via.str.size) == 0) {
                    p_ip = a;
                    continue;
                }
            }

            if (p_delta == NULL || p_ip == NULL) {
                fprintf(stderr, "<3>Received message does not contain all elements\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            if (p_delta->val.type != MSGPACK_OBJECT_STR || p_ip->val.type != MSGPACK_OBJECT_STR) {

                fprintf(stderr, "<3>Received message does not contain right data types\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            char v_delta[V_DELTA_SIZE] = { 0 };
            memset(v_delta, 0, V_DELTA_SIZE);
            strncpy(v_delta, p_delta->val.via.str.ptr, min(p_delta->val.via.str.size, V_DELTA_SIZE - 1));
            char v_ip[V_IP_SIZE] = { 0 };
            memset(v_ip, 0, V_IP_SIZE);
            strncpy(v_ip, p_ip->val.via.str.ptr, min(p_ip->val.via.str.size, V_IP_SIZE - 1));

            if (regexec(&ipv4_regex, v_ip, 0, NULL, 0) != 0) {
                fprintf(stderr, "<3>Received message does not contain IPv4, got '%s'\n", v_ip);
                break;
            }

            fprintf(stdout, "<7>%s %s\n", (strcmp(v_delta, "positive") == 0) ? "Add" : "Remove", v_ip);
            char line[LINE_SIZE] = { 0 };
            memset(line, 0, LINE_SIZE);
            snprintf(line, LINE_SIZE, "%s dynfw4 %s -exist", (strcmp(v_delta, "positive") == 0) ? "add" : "del", v_ip);
            if (ipset_parse_line(ipset, line) < 0) {
                fprintf(stderr, "<3>Could not execute ipset statement '%s'\n", line);
            }
        } while (false);
    }
    msgpack_unpacked_destroy(&unpacked);
}

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    setlinebuf(stdout);
    setlinebuf(stderr);

    fprintf(stderr, "%s %s\n", "dynfwd", GIT_VERSION);

    if (chdir("/proc") != 0) {
        fprintf(stderr, "Could not chdir to /proc: %s\n", strerror(errno));
        goto fail;
    }
    /*
        none of our children will keep privs received via ambient capabilities,
        none of our children will ever be granted more privs,
        escape via ptrace is impossible,
    */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
        || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {

        fprintf(stderr, "Unable to initialize secure subsystem\n");
        goto fail;
    }

    extern int optind;
    extern int opterr;
    extern int optopt;
    extern char *optarg;
    int optc = -1;

    while ((optc = getopt(argc, argv, ":Vh")) != -1) {
        switch (optc) {
            case 'V':
                fprintf(stderr, "%s %s\n", "dynfwd", GIT_VERSION);
                ret = EXIT_SUCCESS;
                goto fail;

            case 'h':
                fprintf(stderr, "...\n");
                ret = EXIT_SUCCESS;
                goto fail;

            case ':':
                fprintf(stderr, "Option '%c' requires an argument\n", optopt);
                fprintf(stderr, "For usage options run '... -h'\n");
                goto fail;

            default:
            case '?':
                fprintf(stderr, "'%c' is an unknown option\n", optopt);
                fprintf(stderr, "For usage options run '... -h'\n");
                goto fail;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Extra argument '%s' not understood\n", argv[optind]);
        fprintf(stderr, "For usage options run '... -h'\n");
        goto fail;
    }

    if (regcomp(&ipv4_regex, "^([0-9]{1,3}\\.){3}[0-9]{1,3}$", REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(stderr, "<3>Could not compile IPv4 regex\n");
        goto fail;
    }
    if (regcomp(&ipv6_regex, "^([0-9a-f]{0,4}:){7}[0-9a-f]{0,4}$", REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
        fprintf(stderr, "<3>Could not compile IPv6 regex\n");
        goto fail;
    }

    ipset_load_types();
    ipset = ipset_init();
    if (!ipset) {
        fprintf(stderr, "<3>Could not initialize ipset support\n");
        goto fail;
    }

    int major = 0, minor = 0, patch = 0;
    zmq_version(&major, &minor, &patch);
    fprintf(stderr, "<6>Current 0MQ version is %d.%d.%d\n", major, minor, patch);

    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);

    const char *server_public_key = "D=rkicUyn5AcL)>9$2Db0HIELd2F*WaS-zDTikU*";
    char client_public_key[41]; /* 40 + \0 */
    char client_secret_key[41]; /* 40 + \0 */

    zmq_curve_keypair(client_public_key, client_secret_key);
    client_public_key[40] = '\0';
    client_secret_key[40] = '\0';
    zmq_setsockopt(subscriber, ZMQ_CURVE_SERVERKEY, server_public_key, 40);
    zmq_setsockopt(subscriber, ZMQ_CURVE_PUBLICKEY, client_public_key, 40);
    zmq_setsockopt(subscriber, ZMQ_CURVE_SECRETKEY, client_secret_key, 40);
    fprintf(stderr, "<6>Server pub key = %s\n", server_public_key);
    fprintf(stderr, "<6>Client pub key = %s\n", client_public_key);
    fprintf(stderr, "<6>Client sec key = %s\n", client_secret_key);

    zmq_connect(subscriber, "tcp://sentinel.turris.cz:7087");

    /* this is not an error, 0MQ does not take \0 string termination => only 11 bytes */
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "dynfw/delta", 11);
    /* this is not an error, 0MQ does not take \0 string termination => only 10 bytes */
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "dynfw/list", 10);

    if (signal(SIGTERM, signal_handler) == SIG_ERR
        || signal(SIGINT, signal_handler) == SIG_ERR
        || signal(SIGUSR1, signal_handler) == SIG_ERR) {

        fprintf(stderr, "<3>Could not set signal handlers\n");
        goto fail;
    }

    zmq_pollitem_t poll[] = { {subscriber, -1, ZMQ_POLLIN, 0} };

    while (!request_terminate) {
        int res = zmq_poll(poll, 1, 0);

        if (res == 0) {
            /* nothing to process */
            /* 250 ms */
            usleep(250 * 1000);
            continue;
        } else if (res <= 0) {
            fprintf(stderr, "<3>Error during 0MQ polling, %s\n", zmq_strerror(zmq_errno()));
            /* 250 ms */
            usleep(250 * 1000);
            continue;
        }

        /* received topic */
        char topic[TOPIC_SIZE] = { 0 };

        int received_size = 0;
        zmq_msg_t msg;
        void *msg_data = NULL;
        size_t msg_data_size = 0;

        /* topic */
        zmq_msg_init(&msg);
        received_size = zmq_msg_recv(&msg, subscriber, ZMQ_DONTWAIT);
        if (received_size > 0) {
            msg_data = zmq_msg_data(&msg);
            msg_data_size = zmq_msg_size(&msg);
            memset(topic, 0, TOPIC_SIZE);
            strncpy(topic, msg_data, min(msg_data_size, TOPIC_SIZE - 1));
        }
        zmq_msg_close(&msg);

        /* payload */
        zmq_msg_init(&msg);
        received_size = zmq_msg_recv(&msg, subscriber, ZMQ_DONTWAIT);
        if (received_size > 0) {
            msg_data = zmq_msg_data(&msg);
            msg_data_size = zmq_msg_size(&msg);
            if (strcmp("dynfw/delta", topic) == 0) {
                process_delta(msg_data, msg_data_size);
            }
            if (strcmp("dynfw/list", topic) == 0) {
                fprintf(stderr, "<6>Switching %s dynfw/list\n", "off");
                /* this is not an error, 0MQ does not take \0 string termination */
                zmq_setsockopt(subscriber, ZMQ_UNSUBSCRIBE, "dynfw/list", 10);
                process_list(msg_data, msg_data_size);
            }
        }
        zmq_msg_close(&msg);

        if (request_reload) {
            fprintf(stderr, "<6>Switching %s dynfw/list\n", "on");
            /* this is not an error, 0MQ does not take \0 string termination */
            zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "dynfw/list", 10);
            request_reload = false;
        }
    }

    zmq_close(subscriber);
    zmq_ctx_destroy(context);

    ipset_fini(ipset);

    regfree(&ipv4_regex);
    regfree(&ipv6_regex);

    ret = EXIT_SUCCESS;
fail:

    return ret;
}
