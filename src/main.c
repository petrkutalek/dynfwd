// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>             // for size_t
#include <limits.h>             // for PATH_MAX
#include <signal.h>
#include <regex.h>

#include <errno.h>
#include <unistd.h>             // getopt
#include <getopt.h>

#include <zmq.h>
#include <msgpack.h>
#include <libipset/ipset.h>

#define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

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

            struct ipset_session *session = ipset_session(ipset);

            ipset_parse_line(ipset, "create dynfw4_tmp hash:ip -exist");
            for (unsigned int j = 0; j != p_list->val.via.array.size; ++j) {
                msgpack_object *p_ip = p_list->val.via.array.ptr + j;

                char v_ip[39] = { 0 };
                memset(v_ip, 0, 39);
                strncpy(v_ip, p_ip->via.str.ptr, min(p_ip->via.str.size, 38));

                if (regexec(&ipv4_regex, v_ip, 0, NULL, 0) != 0) {
                    fprintf(stderr, "<3>Received message does not contain IPv4, got '%s'\n", v_ip);
                    continue;
                }

                char line[64] = { 0 };
                memset(line, 0, 64);
                snprintf(line, 64, "add dynfw4_tmp %s -exist", v_ip);
                ipset_parse_line(ipset, line);
            }
            ipset_parse_line(ipset, "swap dynfw4_tmp dynfw4");
            ipset_parse_line(ipset, "destroy dynfw4_tmp");
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

            if (p_delta->val.type != MSGPACK_OBJECT_STR
                || p_ip->val.type != MSGPACK_OBJECT_STR) {

                fprintf(stderr, "<3>Received message does not contain right data types\n");
                msgpack_object_print(stderr, unpacked.data);
                break;
            }

            char v_delta[16] = { 0 };
            memset(v_delta, 0, 16);
            strncpy(v_delta, p_delta->val.via.str.ptr, min(p_delta->val.via.str.size, 15));
            char v_ip[39] = { 0 };
            memset(v_ip, 0, 39);
            strncpy(v_ip, p_ip->val.via.str.ptr, min(p_ip->val.via.str.size, 38));

            if (regexec(&ipv4_regex, v_ip, 0, NULL, 0) != 0) {
                fprintf(stderr, "<3>Received message does not contain IPv4, got '%s'\n", v_ip);
                break;
            }

            char line[64] = { 0 };
            memset(line, 0, 64);
            snprintf(line, 64, "%s dynfw4 %s -exist", (strcmp(v_delta, "positive") == 0) ? "add" : "del", v_ip);
            if (ipset_parse_line(ipset, line) < 0) {
                fprintf(stderr, "<3>Could not execute ipset statement '%s'\n", line);
            }
            //fprintf(stdout, "<7>%s %s\n", (strcmp(v_delta, "positive") == 0) ? "+" : "-", v_ip);
        } while (false);
    }
    msgpack_unpacked_destroy(&unpacked);
}

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    setlinebuf(stdout);

    extern int optind;
    extern int opterr;
    extern int optopt;
    extern char *optarg;
    int optc = -1;

    while ((optc = getopt(argc, argv, ":Vh")) != -1) {
        switch (optc) {
            case 'V':
                fprintf(stderr, "%s %s\n", argv[0], GIT_VERSION);
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

    if (regcomp(&ipv4_regex, "^([0-9]{1,3}\\.){3}[0-9]{1,3}$", REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(stderr, "<3>Could not compile IPv4 regex\n");
        goto fail;
    }
    if (regcomp(&ipv6_regex, "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(stderr, "<3>Could not compile IPv6 regex\n");
        goto fail;
    }

    ipset_load_types();
    ipset = ipset_init();
    if (!ipset) {
        fprintf(stderr, "<3>Could not initialize ipset support\n");
        goto fail;
    }

/*
    int major, minor, patch;
    zmq_version(&major, &minor, &patch);
    fprintf(stderr, "current 0MQ version is %d.%d.%d\n", major, minor, patch);
*/

    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);

    const char *server_public_key = "D=rkicUyn5AcL)>9$2Db0HIELd2F*WaS-zDTikU*";
    char client_public_key[41];
    char client_secret_key[41];

    zmq_curve_keypair(client_public_key, client_secret_key);
    zmq_setsockopt(subscriber, ZMQ_CURVE_SERVERKEY, server_public_key, 40);
    zmq_setsockopt(subscriber, ZMQ_CURVE_PUBLICKEY, client_public_key, 40);
    zmq_setsockopt(subscriber, ZMQ_CURVE_SECRETKEY, client_secret_key, 40);
    fprintf(stderr, "<6>server pub key = %s\n", server_public_key);
    fprintf(stderr, "<6>client pub key = %s\n", client_public_key);
    fprintf(stderr, "<6>client sec key = %s\n", client_secret_key);

    zmq_connect(subscriber, "tcp://sentinel.turris.cz:7087");

    /* this is not an error, 0MQ does not take \0 string termination */
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "dynfw/delta", 11);
    /* this is not an error, 0MQ does not take \0 string termination */
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "dynfw/list", 10);

    if (signal(SIGTERM, signal_handler) == SIG_ERR
        || signal(SIGINT, signal_handler) == SIG_ERR
        || signal(SIGUSR1, signal_handler) == SIG_ERR) {

        fprintf(stderr, "<3>Could not set signal handlers\n");
        goto fail;
    }

    zmq_pollitem_t poll[1] = {
        { subscriber, -1, ZMQ_POLLIN, 0 }
    };

    while (!request_terminate) {
        int res = zmq_poll(poll, 1, 0);

        if (res == 0) {
            usleep(100 * 1000);
            continue;
        } else if (res <= 0) {
            fprintf(stderr, "<3>Error during 0MQ polling, %s\n", zmq_strerror(zmq_errno()));
            usleep(100 * 1000);
            continue;
        }

        char topic[32] = { 0 };

        zmq_msg_t msg;
        int size = 0;
        void *data = NULL;
        size_t data_size = 0;

        zmq_msg_init(&msg);
        size = zmq_msg_recv(&msg, subscriber, ZMQ_DONTWAIT);
        if (size > 0) {
            data = zmq_msg_data(&msg);
            data_size = zmq_msg_size(&msg);
            memset(topic, 0, 32);
            strncpy(topic, data, min(data_size, 31));
        }
        zmq_msg_close(&msg);

        zmq_msg_init(&msg);
        size = zmq_msg_recv(&msg, subscriber, ZMQ_DONTWAIT);
        if (size > 0) {
            data = zmq_msg_data(&msg);
            data_size = zmq_msg_size(&msg);
            if (strcmp("dynfw/delta", topic) == 0) {
                process_delta(data, data_size);
            }
            if (strcmp("dynfw/list", topic) == 0) {
                fprintf(stderr, "<6>Switching %s dynfw/list\n", "off");
                /* this is not an error, 0MQ does not take \0 string termination */
                zmq_setsockopt(subscriber, ZMQ_UNSUBSCRIBE, "dynfw/list", 10);
                process_list(data, data_size);
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
