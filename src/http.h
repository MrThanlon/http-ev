//
// Created by Ziyi Huang on 2021/9/21.
//

#ifndef TEST_C_HTTP_H
#define TEST_C_HTTP_H

#include <ev.h>
#include <llhttp.h>

typedef struct http_string_s http_string_t;
typedef struct http_header_field_s http_header_field_t;
typedef struct http_headers_s http_headers_t;
typedef struct http_response_s http_response_t;
typedef struct http_request_s http_request_t;
typedef struct http_url_trie_node_s http_url_trie_node_t;
typedef struct http_server_s http_server_t;
typedef enum llhttp_method http_method_t;
typedef struct http_context_s http_context_t;
typedef unsigned int (*http_handler_t)(http_context_t* context);
typedef void (*http_err_handler)(int err);

struct http_string_s {
    size_t len;
    unsigned char *data;
};

struct http_header_field_s {
    http_string_t key;
    http_string_t value;
};

struct http_headers_s {
    size_t len;
    size_t capacity;
    http_header_field_t *fields;
};

struct http_request_s {
    http_method_t method;
    http_string_t url;
    http_headers_t headers;
    http_string_t body;
};

struct http_response_s {
    http_headers_t headers;
    http_string_t body;
};

struct http_context_s {
    ev_io watcher;
    llhttp_t parser;
    http_server_t* server;
    http_request_t request;
    http_response_t response;
    char *buffer;
    size_t buffer_ptr;
    size_t buffer_capacity;
    char ready_to_close;
    int flags;
};

struct http_url_trie_node_s {
    // code for 37(%) to 126(~)
    http_url_trie_node_t *children[89];
    http_handler_t handler;
};

enum {
    HTTP_O_NOT_FREE_RESPONSE_BODY = 0b1,
    HTTP_O_NOT_FREE_RESPONSE_HEADER = 0b10,
};

// TODO: bind address
struct http_server_s {
    struct ev_loop *loop;
    ev_io tcp_watcher;
    int port;
    http_url_trie_node_t url_root;
    llhttp_settings_t parser_settings;
    http_err_handler err_handler;
};

http_server_t *http_create_server(void);
int http_server_run(http_server_t *server);
int http_register_url(http_server_t *server, const char *url, http_handler_t handler);
int http_register_static_dir(http_server_t *server, const char *url, const char *dir);

#endif //TEST_C_HTTP_H
