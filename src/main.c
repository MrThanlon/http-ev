#include "http.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

unsigned int handler(http_context_t* context) {
    return http_send_file(context, "/Users/ziyihuang/source/http-ev", "index.html");
}

void err_handler(int err) {
    perror("error");
}

int main(void) {
    http_server_t *server = http_create_server();
    server->port = 19134;
    http_register_url(server, "/", handler);
    server->err_handler = err_handler;
    server->backlog = 100;
    if(http_server_run(server)) {
        perror("Failed to start server");
        return errno;
    }
    return 0;
}
