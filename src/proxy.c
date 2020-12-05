#include <zmq.h>

int main(void)
{
    /* 0MQ */
    void *context = zmq_ctx_new();

    /* upstream */
    void *subscriber = zmq_socket(context, ZMQ_XSUB);
    const char *server_public_key = "D=rkicUyn5AcL)>9$2Db0HIELd2F*WaS-zDTikU*";
    char client_public_key[41];
    char client_secret_key[41];
    zmq_curve_keypair(client_public_key, client_secret_key);
    zmq_setsockopt(subscriber, ZMQ_CURVE_SERVERKEY, server_public_key, 41);
    zmq_setsockopt(subscriber, ZMQ_CURVE_PUBLICKEY, client_public_key, 41);
    zmq_setsockopt(subscriber, ZMQ_CURVE_SECRETKEY, client_secret_key, 41);
    zmq_connect(subscriber, "tcp://sentinel.turris.cz:7087");

    /* clients */
    void *publisher = zmq_socket(context, ZMQ_XPUB);
    zmq_bind(publisher, "tcp://*:7087");

    /* proxy */
    zmq_proxy(subscriber, publisher, NULL);

    /* unreachable, clean-up */
    zmq_close(publisher);
    zmq_close(subscriber);
    zmq_ctx_destroy(context);

    return 0;
}
