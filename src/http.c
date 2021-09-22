//
// Created by Ziyi Huang on 2021/9/21.
//

#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <errno.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024

static http_context_t *get_context_from_parser(llhttp_t *parser) {
    return (http_context_t *) ((void *) parser - offsetof(http_context_t, parser));
}

static char *get_status_message(unsigned int status) {
    switch (status) {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 102:
            return "Processing";
        case 103:
            return "Early Hints";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 207:
            return "Multi-Status";
        case 208:
            return "Already Reported";
        case 226:
            return "IM Used";
        case 300:
            return "300";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 306:
            return "Switch Proxy";
        case 307:
            return "Temporary Redirect";
        case 308:
            return "Permanent Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Require";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Request Entity Too Large";
        case 414:
            return "Request-URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Requested Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 418:
            return "I'm a teapot";
        case 421:
            return "Misdirected Request";
        case 422:
            return "Unprocessable Entity";
        case 423:
            return "Locked";
        case 424:
            return "Failed Dependency";
        case 425:
            return "Too Early";
        case 426:
            return "Upgrade Required";
        case 428:
            return "Precondition Required";
        case 429:
            return "Too Many Requests";
        case 431:
            return "Request Header Fields Too Large";
        case 440:
            return "Login Time-out";
        case 451:
            return "Unavailable For Legal Reasons";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        case 506:
            return "Variant Also Negotiates";
        case 507:
            return "Insufficient Storage";
        case 508:
            return "Loop Detected";
        case 510:
            return "Not Extended";
        case 511:
            return "Network Authentication Required";
        default:
            return "Unknown";
    }
}

static void close_context(http_context_t *context) {
    close(context->watcher.fd);
    ev_io_stop(context->server->loop, &context->watcher);
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_BODY) && (context->response.body.data != NULL)) {
        free(context->response.body.data);
    }
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_HEADER) && (context->response.headers.fields != NULL)) {
        free(context->response.headers.fields);
    }
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);
}

static void http_dispatch(http_context_t *context) {
    // search url
    http_url_trie_node_t *node = &context->server->url_root;
    http_handler_t handler = node->handler;
    size_t idx = 1;
    while (idx < context->request.url.len && node != NULL) {
        if (node->handler != NULL) {
            handler = node->handler;
        }
        node = node->children[context->request.url.data[idx] - '%'];
        idx += 1;
    }
    // run handler
    if (handler != NULL) {
        // TODO: multithreading
        unsigned int status = handler(context);
        FILE *socket_f = fdopen(context->watcher.fd, "w");
        fprintf(socket_f, "HTTP/1.1 %u %s\r\n", status, get_status_message(status));
        for (size_t i = 0; i < context->response.headers.len; i++) {
            fprintf(socket_f,
                    "%.*s: %.*s\r\n",
                    (int)context->response.headers.fields[i].key.len,
                    context->response.headers.fields[i].key.data,
                    (int)context->response.headers.fields[i].value.len,
                    context->response.headers.fields[i].value.data
            );
        }
        // Content-Length
        fprintf(socket_f, "Content-Length: %zu\r\n\r\n", context->response.body.len);
        fflush(socket_f);
        // body
        fwrite(context->response.body.data, context->response.body.len, 1, socket_f);
        fclose(socket_f);
    } else {
        // 404
        write(context->watcher.fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 45);
    }
    context->ready_to_close = 0x7f;
}

static int url_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    context->request.url.data = (unsigned char *) at;
    context->request.url.len = length;
    context->request.method = parser->method;
    return 0;
}

static int header_field_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    http_headers_t *headers = &context->request.headers;
    if (headers->len >= headers->capacity) {
        // expansion
        headers->capacity += 10;
        headers->fields = realloc(headers->fields, headers->capacity * sizeof(http_header_field_t));
        if (headers->fields == NULL) {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            context->ready_to_close = 0x7f;
            return -1;
        }
    }
    headers->fields[headers->len].key.data = (unsigned char *) at;
    headers->fields[headers->len].key.len = length;
    headers->len += 1;
    return 0;
}

static int header_value_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    http_headers_t *headers = &context->request.headers;
    headers->fields[headers->len - 1].value.data = (unsigned char *) at;
    headers->fields[headers->len - 1].value.len = length;
    return 0;
}

static int body_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    context->request.body.data = (unsigned char *) at;
    context->request.body.len = length;
    return 0;
}

static int message_complete_cb(llhttp_t *parser) {
    http_dispatch(get_context_from_parser(parser));
    return 0;
}

static void tcp_read_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_context_t *context = (http_context_t *) watcher;
    if (EV_ERROR & revents) {
        // error, close
        close_context(context);
        return;
    }
    // receive message, TODO: use mmap
    ssize_t bytes = read(watcher->fd,
                         context->buffer + context->buffer_ptr,
                         context->buffer_capacity - context->buffer_ptr);
    if (bytes < 0) {
        // error or close
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        close_context(context);
    } else if (bytes == 0) {
        close_context(context);
    } else {
        // received
        if (context->buffer_ptr + bytes >= context->buffer_capacity) {
            // expansion
            context->buffer_capacity += BUFFER_SIZE;
            context->buffer = realloc(context->buffer, context->buffer_capacity);
            if (context->buffer == NULL) {
                // error, close
                if (context->server->err_handler != NULL) {
                    context->server->err_handler(errno);
                }
                close_context(context);
                return;
            }
        }
        // execute parser
        enum llhttp_errno err = llhttp_execute(&context->parser, context->buffer + context->buffer_ptr, bytes);
        if (err == HPE_OK) {
            context->buffer_ptr += bytes;
            if (context->ready_to_close) {
                close_context(context);
            }
        } else {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            close_context(context);
        }
    }
}

static void tcp_accept_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        return;
    }
    // accept
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    client_fd = accept(watcher->fd, (struct sockaddr *) &addr, &addr_len);
    if (client_fd < 0) {
        // error
        return;
    }
    // init context
    http_context_t *context = (http_context_t *) malloc(sizeof(http_context_t));
    // memset(context, 0, sizeof(http_context_t));
    context->ready_to_close = 0;
    context->server = (http_server_t *) ((void *) watcher - offsetof(http_server_t, tcp_watcher));
    llhttp_init(&context->parser, HTTP_REQUEST, &context->server->parser_settings);
    // init buffer
    context->buffer_ptr = 0;
    context->buffer = (char *) malloc(BUFFER_SIZE);
    if (context->buffer == NULL) {
        // error, close
        close(client_fd);
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        free(context);
        return;
    }
    context->buffer_capacity = BUFFER_SIZE;
    // init request header buffer
    context->request.headers.len = 0;
    context->request.headers.capacity = 10;
    context->request.headers.fields = malloc(10 * sizeof(http_header_field_t));
    if (context->request.headers.fields == NULL) {
        // error, close
        close(client_fd);
        free(context->buffer);
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        free(context);
        return;
    }
    // init response header
    context->response.headers.fields = NULL;
    context->response.headers.len = 0;
    context->response.headers.capacity = 0;
    // join loop
    ev_io_init(&context->watcher, tcp_read_cb, client_fd, EV_READ);
    ev_io_start(loop, &context->watcher);
}

int http_register_url(http_server_t *server, const char *url, http_handler_t handler) {
    // url[0] must be '/'
    if (url[0] != '/') {
        return -1;
    }
    // insert to trie node
    http_url_trie_node_t *node = &server->url_root;
    size_t idx = 1;
    while (url[idx] >= '%' && url[idx] <= '~') {
        char offset = url[idx] - '%';
        if (node->children[offset] == NULL) {
            // new node
            node->children[offset] = malloc(sizeof(http_url_trie_node_t));
            if (node->children[offset] == NULL) {
                // error
                if (server->err_handler != NULL) {
                    server->err_handler(errno);
                }
                return errno;
            }
        }
        node = node->children[offset];
        idx += 1;
    }
    node->handler = handler;
    return 0;
}

// TODO: register URL as static directories
int http_register_static_dir(http_server_t *server, const char *url, const char *dir) {
    return 0;
}

http_server_t *http_create_server(void) {
    http_server_t *server = malloc(sizeof(http_server_t));
    memset(server, 0, sizeof(http_server_t));
    if (server == NULL) {
        return server;
    }
    server->loop = EV_DEFAULT;
    server->port = 80;
    llhttp_settings_init(&server->parser_settings);
    server->parser_settings.on_url = url_cb;
    server->parser_settings.on_header_field = header_field_cb;
    server->parser_settings.on_header_value = header_value_cb;
    server->parser_settings.on_body = body_cb;
    server->parser_settings.on_message_complete = message_complete_cb;
    server->err_handler = NULL;
    return server;
}

int http_server_run(http_server_t *server) {
    // open port
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr))) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    if (listen(socket_fd, 2)) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    // join loop
    ev_io_init(&server->tcp_watcher, tcp_accept_cb, socket_fd, EV_READ);
    ev_io_start(server->loop, &server->tcp_watcher);
    // run loop
    return ev_run(server->loop, 0);
}
