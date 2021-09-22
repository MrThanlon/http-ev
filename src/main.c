#include "http.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

unsigned int handler(http_context_t* context) {
    printf("request %.*s\n", (int)context->request.url.len, context->request.url.data);
    const size_t len = context->request.url.len + 13;
    context->response.body.len = len;
    context->response.body.data = (unsigned char*) malloc(len);
    memcpy(context->response.body.data, "Request URL: ", 13);
    memcpy(context->response.body.data + 13, context->request.url.data, context->request.url.len);
    return 200;
}

void err_handler(int err) {
    perror("error");
}

int main(void) {
    http_server_t *server = http_create_server();
    server->port = 19134;
    http_register_url(server, "/", handler);
    server->err_handler = err_handler;
    if(http_server_run(server)) {
        perror("Failed to start server");
        return errno;
    }
    return 0;
}
