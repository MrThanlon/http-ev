//
// Created by Ziyi Huang on 2021/9/21.
//

#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#if __APPLE__

#include <sys/uio.h>

#elif __linux__

#include <sys/sendfile.h>
#include <sys/prctl.h>

#endif

#define BUFFER_SIZE 4096
#define CONTEXT_POOL_SIZE 512
#define DEBUG 1

static http_context_t *get_context_from_parser(llhttp_t *parser) {
    return (http_context_t *) ((void *) parser - offsetof(http_context_t, parser));
}

static http_context_t *get_context_from_write_watcher(ev_io *write_watcher) {
    return (http_context_t *) ((void *) write_watcher - offsetof(http_context_t, write_watcher));
}

static const char *get_status_message(unsigned int status) {
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

/**
 * Reset context but not free memory, for recycling context.
 * @param context
 */
static void reset_context(http_context_t *context) {
    context->ready_to_close = 0;
    context->state = HTTP_CONTEXT_STATE_PARSING;
    // reset parser
    llhttp_reset(&context->parser);
    // reset buffer, but not free memory
    context->buffer_ptr = 0;
    // reset request
    context->request.url.len = 0;
    context->request.headers.len = 0;
    context->request.body.len = 0;
    // reset response
    context->response.headers.len = 0;
    context->response.body.len = 0;
}

static http_context_t *pool[CONTEXT_POOL_SIZE];
static size_t pool_ptr = 0;
ev_timer timer_watcher;

/**
 * Free context memory.
 * @param context
 */
static void free_context(http_context_t *context) {
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);
}

static void timer_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
#if DEBUG
    printf("%zu context(s) in pool, free one\n", pool_ptr);
#endif
    pool_ptr -= 1;
    free_context(pool[pool_ptr]);
    if (pool_ptr > 0) {
        watcher->repeat = 1;
        ev_timer_again(loop, watcher);
    }
}
// TODO: use a better free policy, use lock-free queue
/**
 * Recycle used context to pool.
 * @param context
 */
static void recycle_context(http_context_t *context) {
    // recycle
    if (pool_ptr < CONTEXT_POOL_SIZE) {
        reset_context(context);
        pool[pool_ptr++] = context;
        // TODO: add timer to free
        if (!timer_watcher.active) {
            // ev_timer_init(&timer_watcher, timer_cb, 1, 0);
            // ev_timer_start(EV_DEFAULT, &timer_watcher);
        }
    } else {
        // full
        free_context(context);
    }
}

/**
 * Get a new context from pool, or create one.
 * @return context
 */
static http_context_t *get_new_context() {
    http_context_t *context;
    if (pool_ptr > 0) {
        // reuse
        pool_ptr -= 1;
        context = pool[pool_ptr];
        if (pool_ptr == 0) {
            // stop timer
            // ev_timer_stop(EV_DEFAULT, &timer_watcher);
        }
    } else {
        // empty
        context = (http_context_t *) malloc(sizeof(http_context_t));
        bzero(context, sizeof(http_context_t));
        // init request buffer
        context->buffer = (char *) malloc(BUFFER_SIZE);
        if (context->buffer == NULL) {
            // error, close
            free(context);
            return NULL;
        }
        context->buffer_capacity = BUFFER_SIZE;
        // init request header buffer
        context->request.headers.capacity = 10;
        context->request.headers.fields = malloc(10 * sizeof(http_header_field_t));
        if (context->request.headers.fields == NULL) {
            // error, close
            free(context->buffer);
            free(context);
            return NULL;
        }
    }
    return context;
}

/**
 * Close connection and recycle context.
 * @param context
 */
static void close_context(http_context_t *context) {
    ev_io_stop(context->server->loop, &context->watcher);
    close(context->watcher.fd);
    recycle_context(context);
    /*
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_BODY) && (context->response.body.data != NULL)) {
        free(context->response.body.data);
    }
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_HEADER) && (context->response.headers.fields != NULL)) {
        free(context->response.headers.fields);
    }
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);*/
}

static void tcp_write_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_context_t *context = get_context_from_write_watcher(watcher);
}

/**
 * Call this to indicate handle finished.
 * @param context
 */
void http_next(http_context_t *context) {
    context->state = HTTP_CONTEXT_STATE_RESPONSE;
    // TODO: generate header string
    // TODO: write callback
}

/**
 * Dispatch context to handler. TODO: update
 * @param context
 */
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
        if (context->ready_to_close) {
            // already handled, return
            return;
        }
        // TODO: use write callback
        FILE *socket_f = fdopen(context->watcher.fd, "w");
        fprintf(socket_f, "HTTP/1.1 %u %s\r\n", status, get_status_message(status));
        for (size_t i = 0; i < context->response.headers.len; i++) {
            fprintf(socket_f,
                    "%.*s: %.*s\r\n",
                    (int) context->response.headers.fields[i].key.len,
                    context->response.headers.fields[i].key.data,
                    (int) context->response.headers.fields[i].value.len,
                    context->response.headers.fields[i].value.data
            );
        }
        // body
        if (status != 200 && context->response.body.len == 0) {
            // FIXME: default err body
            // Content-Length
            fprintf(socket_f, "Content-Length: %zu\r\n\r\n", strlen(get_status_message(status)));
            fputs(get_status_message(status), socket_f);
        } else {
            // Content-Length
            fprintf(socket_f, "Content-Length: %zu\r\n\r\n", context->response.body.len);
            fwrite(context->response.body.data, context->response.body.len, 1, socket_f);
        }
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
        http_header_field_t *new_fields = (http_header_field_t *)
                realloc(headers->fields, headers->capacity * sizeof(http_header_field_t));
        if (new_fields == NULL) {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            context->ready_to_close = 0x7f;
            return -1;
        }
        headers->fields = new_fields;
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

static int set_non_block(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return flags;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) return -1;
    return 0;
}

static void tcp_read_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_context_t *context = (http_context_t *) watcher;
    if (EV_ERROR & revents) {
        // error, close
        close_context(context);
        return;
    }
    // receiving message
    ssize_t bytes = read(watcher->fd,
                         context->buffer + context->buffer_ptr,
                         context->buffer_capacity - context->buffer_ptr);
    /*recv(watcher->fd,
         context->buffer + context->buffer_ptr,
         context->buffer_capacity - context->buffer_ptr,
         0);*/
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, continue
            return;
        }
        // error or close
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        close_context(context);
    } else if (bytes == 0) {
        // client close
#if DEBUG
        puts("client close");
#endif
        close_context(context);
    } else {
        // received
        if (context->buffer_ptr + bytes >= context->buffer_capacity) {
            // expansion
            context->buffer_capacity += BUFFER_SIZE;
            char *new_buffer = (char *) realloc(context->buffer, context->buffer_capacity);
            if (new_buffer == NULL) {
                // error, close
                if (context->server->err_handler != NULL) {
                    context->server->err_handler(errno);
                }
                close_context(context);
                return;
            }
            context->buffer = new_buffer;
        }
        // execute parser
        enum llhttp_errno err = llhttp_execute(&context->parser, context->buffer + context->buffer_ptr, bytes);
        if (err == HPE_OK) {
            context->buffer_ptr += bytes;
            if (context->ready_to_close) {
#if DEBUG
                static size_t counts = 0;
                counts += 1;
                printf("context over, %zu request\n", counts);
#endif
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
    http_server_t *server = (http_server_t *) ((void *) watcher - offsetof(http_server_t, tcp_watcher));
    if (errno == ENFILE) {
        // unable to accept, close
        close(client_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return;
    }
    if (set_non_block(client_fd)) {
        // failed to set non-block
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        close(client_fd);
        return;
    }
    // operate context
    http_context_t *context = get_new_context();
    if (context == NULL) {
        // failed, close
        close(client_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return;
    }
    context->server = server;
    // init llhttp
    llhttp_init(&context->parser, HTTP_REQUEST, &server->parser_settings);
    // join loop
    ev_io_init(&context->watcher, tcp_read_cb, client_fd, EV_READ);
    ev_io_start(loop, &context->watcher);
}

// TODO: use lock-free queue
/**
 * Pop fd from blocking-queue.
 * @param queue
 * @return
 */
static int queue_pop(http_fd_queue_t *queue) {
    // use pthread_mutex
    http_fd_queue_node_t *head = queue->dummy_node.next;
    pthread_mutex_lock(&queue->lock);
    while (head != NULL) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }
    int fd = head->fd;
    queue->dummy_node.next = head->next;
    pthread_mutex_unlock(&queue->lock);
    free(head);
    return fd;
}

/**
 * Push fd to blocking-queue.
 * @param queue
 * @param fd
 */
static void queue_push(http_fd_queue_t *queue, int fd) {
    http_fd_queue_node_t *node = (http_fd_queue_node_t *) malloc(sizeof(http_fd_queue_node_t));
    node->fd = fd;
    // use pthread_mutex
    pthread_mutex_lock(&queue->lock);
    queue->tail->next = node;
    queue->tail = node;
    pthread_mutex_unlock(&queue->lock);
    pthread_cond_signal(&queue->cond);
}

static void sub_thread_run(http_server_t *server) {
    http_context_t context;
    reset_context(&context);
    while (1) {
        // reset context
        int client_fd = queue_pop(&server->fd_queue);
    }
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


struct trie_node {
    // 0-9a-z
    struct trie_node *child[36];
    const char *text;
};

static void build_trie(struct trie_node *root, const char *pat, const char *text) {
    struct trie_node *ptr = root;
    for (int i = 0; pat[i] != '\0'; i++) {
        char c = pat[i];
        if (c <= '9') {
            c -= '0';
        } else {
            // c = c - 'a' + 10;
            c -= 'a' - 10;
        }
        if (ptr->child[c] == NULL) {
            // new node
            ptr->child[c] = (struct trie_node *) malloc(sizeof(struct trie_node));
            bzero(ptr->child[c], sizeof(struct trie_node));
        }
        ptr = ptr->child[c];
    }
    ptr->text = text;
}

/**
 * Get MIME type string from postfix.
 * @param postfix_name
 * @return MIME type string.
 */
static const char *get_mime_string(const char *postfix_name) {
    // generate trie
    static struct trie_node *root = NULL;
    if (root == NULL) {
        root = (struct trie_node *) malloc(sizeof(struct trie_node));
        bzero(root, sizeof(struct trie_node));
        build_trie(root, "html", "text/html");
        build_trie(root, "htm", "text/html");
        build_trie(root, "shtml", "text/html");
        build_trie(root, "css", "text/css");
        build_trie(root, "js", "text/javascript");
        build_trie(root, "txt", "text/plain");
        build_trie(root, "gif", "image/gif");
        build_trie(root, "png", "image/png");
        build_trie(root, "jpg", "image/jpeg");
        build_trie(root, "jpeg", "image/jpeg");
        build_trie(root, "tif", "image/tiff");
        build_trie(root, "tiff", "image/tiff");
        build_trie(root, "svg", "image/svg+xml");
        build_trie(root, "mp3", "audio/mpeg");
        build_trie(root, "ogg", "audio/ogg");
        build_trie(root, "3gp", "video/3gpp");
        build_trie(root, "3gpp", "video/3gpp");
        build_trie(root, "mp4", "video/mp4");
        build_trie(root, "mpg", "video/mpeg");
        build_trie(root, "mpeg", "video/mpeg");
        build_trie(root, "webm", "video/webm");
        build_trie(root, "mov", "video/quicktime");
        build_trie(root, "woff", "application/font-woff");
        build_trie(root, "rss", "application/rss+xml");
        build_trie(root, "pdf", "application/pdf");
        build_trie(root, "xml", "application/xml");
        build_trie(root, "json", "application/json");
    }
    // match
    struct trie_node *ptr = root;
    for (size_t i = 0; postfix_name[i] != '\0'; i++) {
        char c = postfix_name[i];
        if (c <= '9' && c >= '0') {
            c -= '0';
        } else if (c >= 'a' && c <= 'z') {
            // c = c - 'a' + 10;
            c -= 'a' - 10;
        } else if (c >= 'A' && c <= 'Z') {
            c -= 'A' - 10;
        } else {
            // application/octet-stream for unknown
            return "application/octet-stream";
        }
        ptr = ptr->child[c];
        if (ptr == NULL) {
            return "application/octet-stream";
        }
    }
    return ptr->text;
}

/**
 * Handle static directories, return 404 if not found.
 * @param context
 * @param path Must be absolute path, `/a/b/c` for example.
 * @param index Default index, `index.html` for example, NULL if not used.
 * @return status code
 */
unsigned int http_send_file(http_context_t *context, const char *path, const char *index) {
    // simplify URL path
    const char *cur = ".";
    const char *fa = "..";
    const size_t STACK_MAX = PATH_MAX / 2;
    size_t stack_head[STACK_MAX];
    size_t stack_len[STACK_MAX];
    size_t stack_ptr = 0;
    size_t st = 1;
    unsigned char *url = context->request.url.data;
    // FIXME: edge condition
    for (size_t i = 1; i <= context->request.url.len; i++) {
        if (url[i] != '/' && url[i - 1] == '/') {
            // start dir
            st = i;
        } else if ((url[i] == '/' && url[i - 1] != '/') || (i == context->request.url.len)) {
            // end
            if (i - st == 2 && url[st] == '.' && url[st + 1] == '.') {
                // return to father, pop
                stack_ptr = stack_ptr > 0 ? stack_ptr - 1 : 0;
            } else if (i - st == 1 && url[st] == '.') {
                // current, do nothing
            } else {
                // push
                stack_head[stack_ptr] = st;
                stack_len[stack_ptr++] = i - st;
            }
        }
    }
    // generate path string
    char real_path[PATH_MAX];
    size_t path_ptr = 0;
    // push default path
    for (; path[path_ptr] != '\0'; path_ptr++) {
        if (path_ptr >= PATH_MAX) {
            // too long
            return 400;
        }
        real_path[path_ptr] = path[path_ptr];
    }
    // append url path
    for (size_t i = 0; i < stack_ptr; i++) {
        real_path[path_ptr++] = '/';
        if (path_ptr + stack_len[i] >= PATH_MAX) {
            return 400;
        }
        memcpy(real_path + path_ptr, url + stack_head[i], stack_len[i]);
        path_ptr += stack_len[i];
    }
    real_path[path_ptr] = '\0';
    // check file and get length
    struct stat file_stat;
    if (stat(real_path, &file_stat)) {
        // not found
        return 404;
    }
    if (S_ISREG(file_stat.st_mode)) {
        // file, do nothing
    } else if (S_ISDIR(file_stat.st_mode)) {
        // directories, append index and retry
        if (real_path[path_ptr - 1] != '/') {
            real_path[path_ptr++] = '/';
            if (path_ptr >= PATH_MAX) {
                return 404;
            }
        }
        if (index == NULL) {
            // forbidden
            return 403;
        }
        // append index
        for (size_t i = 0; index[i] != '\0'; i++) {
            real_path[path_ptr++] = index[i];
            if (path_ptr >= PATH_MAX) {
                return 400;
            }
        }
        if (stat(real_path, &file_stat)) {
            return 403;
        }
    } else {
        // not found
        return 404;
    }
    int fd = open(real_path, O_RDONLY);
    if (fd < 0) {
        return 404;
    }
    // get MIME for Content-Type
    size_t postfix_dot = path_ptr;
    for (; postfix_dot >= 0 && real_path[postfix_dot] != '.' && real_path[postfix_dot] != '/'; postfix_dot--);
    postfix_dot += 1;

#if __APPLE__ || __linux__
    // use sendfile, it will handle all context, send header
    char headers_str[100];
    size_t headers_len = sprintf(
            headers_str,
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lld\r\n\r\n",
            get_mime_string(real_path + postfix_dot),
            file_stat.st_size);
    size_t headers_ptr = 0;
    do {
        headers_ptr += write(context->watcher.fd, headers_str + headers_ptr, headers_len - headers_ptr);
    } while (headers_ptr < headers_len);
    context->ready_to_close = 0x7f;
#endif

    // macOS and linux `sendfile` is different.
#if __APPLE__
    off_t file_len = file_stat.st_size;
    off_t file_ptr = 0;
    struct sf_hdtr hdtr = {
            .headers = NULL,
            .hdr_cnt = 0,
            .trailers = NULL,
            .trl_cnt = 0
    };
    do {
        int err = sendfile(fd, context->watcher.fd, file_ptr, &file_len, &hdtr, 0);
        if (err != 0 && err != EAGAIN) {
            // error
            close(fd);
            if (context->server->err_handler != NULL) {
                context->server->err_handler(err);
            }
            return 500;
        }
        file_ptr += file_len;
        file_len = file_stat.st_size - file_len;
    } while (file_ptr < file_stat.st_size);
#elif __linux__
    size_t file_len = file_stat.st_size;
    off_t file_ptr = 0;
    do {
        int err = sendfile(context->watcher.fd, fd, &file_ptr, file_len);
        if (err != 0 && err != EAGAIN) {
            close(fd);
            if (context->server->err_handler != NULL) {
                context->server->err_handler(err);
            }
            return 500;
        }
        file_len -= file_ptr;
    } while (file_ptr < file_stat.st_size);
    context->ready_to_close = 0x7f;
#else
    // set Content-Type
    static http_header_field_t *content_type = NULL;
    if (content_type == NULL) {
        content_type = (http_header_field_t *) malloc(sizeof(http_header_field_t));
        content_type->key.data = (unsigned char *) "Content-Type";
        content_type->key.len = strlen("Content-Type");
    }
    const char* content_type_str = get_mime_string(real_path + postfix_dot);
    content_type->value.data = (unsigned char *) content_type_str;
    content_type->value.len = strlen(content_type_str);
    context->response.headers.len = 1;
    context->response.headers.fields = content_type;
    // read all to context body
    if (context->response.body.len < file_stat.st_size) {
        context->response.body.data = (unsigned char *) realloc(context->response.body.data, file_stat.st_size);
    }
    context->response.body.len = file_stat.st_size;
    read(fd, context->response.body.data, file_stat.st_size);
#endif
    close(fd);
    return 200;
}

http_server_t *http_create_server(void) {
    http_server_t *server = malloc(sizeof(http_server_t));
    memset(server, 0, sizeof(http_server_t));
    if (server == NULL) {
        return server;
    }
    server->loop = EV_DEFAULT;
    llhttp_settings_init(&server->parser_settings);
    server->parser_settings.on_url = url_cb;
    server->parser_settings.on_header_field = header_field_cb;
    server->parser_settings.on_header_value = header_value_cb;
    server->parser_settings.on_body = body_cb;
    server->parser_settings.on_message_complete = message_complete_cb;
    server->err_handler = NULL;
    // init queue
    server->fd_queue.dummy_node.next = NULL;
    server->fd_queue.tail = &server->fd_queue.dummy_node;
    if (pthread_mutex_init(&server->fd_queue.lock, NULL)) {
        // failed
        free(server);
        return NULL;
    }
    if (pthread_cond_init(&server->fd_queue.cond, NULL)) {
        free(server);
        return NULL;
    }
    // default settings
    server->port = 80;
    server->backlog = 64;
    server->multi_process = 0; // disable multi-process
    server->multi_thread = 0; // disable multi-thread
    server->max_url_len = 4096;
    server->max_headers_size = 102400; // 100K
    server->max_body_size = 1048576; // 1M
    return server;
}

void sig_handler(int sig) {
    // FIXME: close socket fd
#if __APPLE__
    // kill all child process
    kill(0, sig);
#elif __linux__
    // do nothing, child process will handle
#endif
    exit(sig);
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
    if (listen(socket_fd, server->backlog)) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    if (set_non_block(socket_fd)) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    if (server->multi_process) {
        // TODO: multi-process architecture, fork()
        // create process group for killing
        if (setpgid(0, 0)) {
            if (server->err_handler != NULL) {
                server->err_handler(errno);
            }
            return errno;
        }
        // fork
        int pid;
        char is_master_process = 0;
        for (unsigned int i = 0; i < server->multi_process; i++) {
            pid = fork();
            if (pid < 0) {
                // err
                if (server->err_handler != NULL) {
                    server->err_handler(pid);
                }
                // kill all child process
                kill(0, SIGINT);
                return pid;
            } else if (pid == 0) {
                // child process
#if __linux__
                prctl(PR_SET_PDEATHSIG, SIGINT);
#endif
                is_master_process = 0;
                // run loop
                ev_io_init(&server->tcp_watcher, tcp_accept_cb, socket_fd, EV_READ);
                ev_io_start(server->loop, &server->tcp_watcher);
                // run loop
                return ev_run(server->loop, 0);
            } else {
                // master process
                is_master_process = 1;
            }
        }
        if (is_master_process) {
            // handle SIGINT
            signal(SIGINT, sig_handler);
            signal(SIGTERM, sig_handler);
            while (1) {
                // wait child process exit
                pid_t child_pid = -1;
                pid_t exit_pid = wait(&child_pid);
                if (exit_pid < 0) {
                    // err
                } else {
                    // spawn a new process, FIXME: duplicate code
                    pid = fork();
                    if (pid < 0) {
                        // err
                        if (server->err_handler != NULL) {
                            server->err_handler(pid);
                        }
                        return pid;
                    } else if (pid == 0) {
                        // child process
#if __linux__
                        prctl(PR_SET_PDEATHSIG, SIGINT);
#endif
                        is_master_process = 0;
                        // run loop
                        ev_io_init(&server->tcp_watcher, tcp_accept_cb, socket_fd, EV_READ);
                        ev_io_start(server->loop, &server->tcp_watcher);
                        // run loop
                        return ev_run(server->loop, 0);
                    }
                }
            }
        }
        return 0;
    } else {
        // single process
        // join loop
        ev_io_init(&server->tcp_watcher, tcp_accept_cb, socket_fd, EV_READ);
        ev_io_start(server->loop, &server->tcp_watcher);
        // run loop
        return ev_run(server->loop, 0);
    }
}
