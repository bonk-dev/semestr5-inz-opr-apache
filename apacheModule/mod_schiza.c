#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_ssl.h"

#include "apr_atomic.h"
#include "apr_strings.h"
#include "apr_time.h"

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

module AP_MODULE_DECLARE_DATA schiza_module;

APLOG_USE_MODULE(schiza);

#define SCHIZA_CLASSIFY_PATH "/classify"
#define SCHIZA_DEFAULT_TIMEOUT apr_time_from_msec(100)
#define SCHIZA_DEFAULT_BREAKER_THRESHOLD 5
#define SCHIZA_DEFAULT_BREAKER_COOLDOWN apr_time_from_sec(30)
#define SCHIZA_RESPONSE_HEADER_LIMIT 4096

/* r->notes keys, usable in LogFormat as %{schiza-verdict}n and %{schiza-score}n */
#define SCHIZA_NOTE_VERDICT "schiza-verdict"
#define SCHIZA_NOTE_SCORE "schiza-score"

typedef enum
{
    SCHIZA_MODE_UNSET = -1,
    SCHIZA_MODE_BLOCK,
    SCHIZA_MODE_MONITOR,
} schiza_mode;

typedef enum
{
    SCHIZA_VERDICT_ALLOW,
    SCHIZA_VERDICT_BLOCK,
    SCHIZA_VERDICT_ERROR,
} schiza_verdict;

/* -1 / NULL / 0 mean "not set in this server context", resolved by merge and accessors */
typedef struct
{
    int enabled;
    const char *backend; /* as written in the config, for log messages */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    apr_interval_time_t timeout;
    schiza_mode mode;
    int breaker_threshold;
    apr_interval_time_t breaker_cooldown;
} schiza_server_conf;

static apr_uint32_t breaker_failures;
static volatile apr_uint64_t breaker_open_until;

/* ------------------------------------------------------------------------- */
/* Configuration                                                              */
/* ------------------------------------------------------------------------- */

static void *create_server_conf(apr_pool_t *p, server_rec *s)
{
    schiza_server_conf *conf = apr_pcalloc(p, sizeof(*conf));
    conf->enabled = -1;
    conf->timeout = -1;
    conf->mode = SCHIZA_MODE_UNSET;
    conf->breaker_threshold = -1;
    conf->breaker_cooldown = -1;
    return conf;
}

static void *merge_server_conf(apr_pool_t *p, void *base_v, void *add_v)
{
    schiza_server_conf *base = base_v;
    schiza_server_conf *add = add_v;
    schiza_server_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->enabled = add->enabled != -1 ? add->enabled : base->enabled;
    if (add->addrlen != 0) {
        conf->backend = add->backend;
        conf->addr = add->addr;
        conf->addrlen = add->addrlen;
    }
    else {
        conf->backend = base->backend;
        conf->addr = base->addr;
        conf->addrlen = base->addrlen;
    }
    conf->timeout = add->timeout != -1 ? add->timeout : base->timeout;
    conf->mode = add->mode != SCHIZA_MODE_UNSET ? add->mode : base->mode;
    conf->breaker_threshold = add->breaker_threshold != -1 ? add->breaker_threshold : base->breaker_threshold;
    conf->breaker_cooldown = add->breaker_cooldown != -1 ? add->breaker_cooldown : base->breaker_cooldown;
    return conf;
}

static apr_interval_time_t conf_timeout(const schiza_server_conf *conf)
{
    return conf->timeout != -1 ? conf->timeout : SCHIZA_DEFAULT_TIMEOUT;
}

static schiza_mode conf_mode(const schiza_server_conf *conf)
{
    return conf->mode != SCHIZA_MODE_UNSET ? conf->mode : SCHIZA_MODE_BLOCK;
}

static int conf_breaker_threshold(const schiza_server_conf *conf)
{
    return conf->breaker_threshold != -1 ? conf->breaker_threshold : SCHIZA_DEFAULT_BREAKER_THRESHOLD;
}

static apr_interval_time_t conf_breaker_cooldown(const schiza_server_conf *conf)
{
    return conf->breaker_cooldown != -1 ? conf->breaker_cooldown : SCHIZA_DEFAULT_BREAKER_COOLDOWN;
}

static schiza_server_conf *get_conf(server_rec *s)
{
    return ap_get_module_config(s->module_config, &schiza_module);
}

static const char *set_enable(cmd_parms *cmd, void *dummy, int flag)
{
    get_conf(cmd->server)->enabled = flag;
    return NULL;
}

/* set the classification backend address&port */
static const char *set_backend(cmd_parms *cmd, void *dummy, const char *arg)
{
    schiza_server_conf *conf = get_conf(cmd->server);

    char *host;
    char *scope_id;
    apr_port_t port;
    if (apr_parse_addr_port(&host, &scope_id, &port, arg, cmd->pool) != APR_SUCCESS || host == NULL || port == 0) {
        return "SchizaBackend: expected ip:port";
    }

    struct addrinfo hints = {0};
    struct addrinfo *res;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    int rc = getaddrinfo(host, apr_itoa(cmd->pool, port), &hints, &res);
    if (rc != 0) {
        return apr_psprintf(cmd->pool, "SchizaBackend: %s is not a numeric address (%s)", host, gai_strerror(rc));
    }
    memset(&conf->addr, 0, sizeof(conf->addr));
    memcpy(&conf->addr, res->ai_addr, res->ai_addrlen);
    conf->addrlen = res->ai_addrlen;
    conf->backend = arg;
    freeaddrinfo(res);
    return NULL;
}

static const char *set_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    apr_interval_time_t timeout;
    if (ap_timeout_parameter_parse(arg, &timeout, "ms") != APR_SUCCESS || timeout <= 0) {
        return "SchizaTimeout: expected a positive duration, e.g. 100 or 100ms";
    }
    get_conf(cmd->server)->timeout = timeout;
    return NULL;
}

static const char *set_mode(cmd_parms *cmd, void *dummy, const char *arg)
{
    schiza_server_conf *conf = get_conf(cmd->server);
    if (strcasecmp(arg, "block") == 0) {
        conf->mode = SCHIZA_MODE_BLOCK;
    }
    else if (strcasecmp(arg, "monitor") == 0) {
        conf->mode = SCHIZA_MODE_MONITOR;
    }
    else {
        return "SchizaMode: expected block or monitor";
    }
    return NULL;
}

static const char *set_breaker(cmd_parms *cmd, void *dummy, const char *threshold, const char *cooldown)
{
    schiza_server_conf *conf = get_conf(cmd->server);
    char *end;
    long value = strtol(threshold, &end, 10);
    if (*threshold == '\0' || *end != '\0' || value < 0 || value > 1000000) {
        return "SchizaBreaker: threshold must be a non-negative number (0 disables the breaker)";
    }
    conf->breaker_threshold = (int)value;

    if (cooldown != NULL
        && (ap_timeout_parameter_parse(cooldown, &conf->breaker_cooldown, "s") != APR_SUCCESS
            || conf->breaker_cooldown <= 0)) {
        return "SchizaBreaker: cooldown must be a positive duration, e.g. 30 or 30s";
    }
    return NULL;
}

static const command_rec schiza_cmds[] = {
    AP_INIT_FLAG("SchizaEnable", set_enable, NULL, RSRC_CONF,
                 "Classify requests with the Schiza backend (On/Off)"),
    AP_INIT_TAKE1("SchizaBackend", set_backend, NULL, RSRC_CONF,
                  "Backend address: ip:port"),
    AP_INIT_TAKE1("SchizaTimeout", set_timeout, NULL, RSRC_CONF,
                  "Total time budget for one classification, default 100ms"),
    AP_INIT_TAKE1("SchizaMode", set_mode, NULL, RSRC_CONF,
                  "block: answer 403 to suspicious requests; monitor: only record the verdict"),
    AP_INIT_TAKE12("SchizaBreaker", set_breaker, NULL, RSRC_CONF,
                   "Failures in a row before skipping the backend, and for how long (default 5 30s)"),
    {NULL},
};

/* ------------------------------------------------------------------------- */
/* Circuit breaker                                                           */
/* ------------------------------------------------------------------------- */

/*
 * the circuit braker prevents slowing down the entire Apache if the classification API faults
 * example config: `SchizaBreaker 5 30s`
 * in this config, if 5 consequentive requests failed, for the next 30s all requests are `skipped`
 */

static int breaker_is_open(apr_time_t now)
{
    return now < (apr_time_t)apr_atomic_read64(&breaker_open_until);
}

static void breaker_record_success(void)
{
    apr_atomic_set32(&breaker_failures, 0);
}

static void breaker_record_failure(request_rec *r, const schiza_server_conf *conf)
{
    int threshold = conf_breaker_threshold(conf);
    if (threshold == 0) {
        return;
    }
    /* apr_atomic_inc32 returns the old value */
    if (apr_atomic_inc32(&breaker_failures) + 1 >= (apr_uint32_t)threshold) {
        apr_atomic_set32(&breaker_failures, 0);
        apr_atomic_set64(&breaker_open_until, (apr_uint64_t)(apr_time_now() + conf_breaker_cooldown(conf)));
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "schiza: backend %s failed %d times in a row, not classifying for %" APR_TIME_T_FMT "s",
                      conf->backend, threshold, apr_time_sec(conf_breaker_cooldown(conf)));
    }
}

/* ------------------------------------------------------------------------- */
/* Request JSON                                                               */
/* ------------------------------------------------------------------------- */

/* JSON string literal (or null) with the value escaped like in access.log.
 * ap_escape_logitem() output is printable ASCII, so only the backslashes and
 * quotes it produces need escaping again for JSON. */
static const char *json_string(apr_pool_t *p, const char *value)
{
    if (value == NULL) {
        return "null";
    }

    const char *escaped = ap_escape_logitem(p, value);
    apr_size_t length = 0;
    for (const char *c = escaped; *c; c++) {
        length += (*c == '"' || *c == '\\') ? 2 : 1;
    }

    char *out = apr_palloc(p, length + 3);
    char *w = out;
    *w++ = '"';
    for (const char *c = escaped; *c; c++) {
        if (*c == '"' || *c == '\\') {
            *w++ = '\\';
        }
        *w++ = *c;
    }
    *w++ = '"';
    *w = '\0';
    return out;
}

static const char *empty_to_null(const char *value)
{
    return (value != NULL && *value != '\0') ? value : NULL;
}

/* Local time with offset at second precision, the same value as %t in the log */
static const char *json_timestamp(apr_pool_t *p, apr_time_t time)
{
    apr_time_exp_t t;
    apr_time_exp_lt(&t, time);
    long offset = t.tm_gmtoff;
    char sign = offset < 0 ? '-' : '+';
    if (offset < 0) {
        offset = -offset;
    }
    return apr_psprintf(p, "\"%04d-%02d-%02dT%02d:%02d:%02d%c%02ld:%02ld\"",
                        t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
                        sign, offset / 3600, (offset % 3600) / 60);
}

/* builds the JSON payload for the classify endpoint */
static const char *build_request_json(request_rec *r)
{
    apr_pool_t *p = r->pool;

    /* Split the target at the first '?', like the log parser does */
    const char *target = r->unparsed_uri != NULL ? r->unparsed_uri : "";
    const char *question = strchr(target, '?');
    const char *path = question != NULL ? apr_pstrmemdup(p, target, question - target) : target;
    const char *query = question != NULL ? question + 1 : NULL;

    const char *tls = NULL;
    if (ap_ssl_conn_is_ssl(r->connection)) {
        tls = empty_to_null(ap_ssl_var_lookup(p, r->server, r->connection, r, "SSL_PROTOCOL"));
    }

    return apr_pstrcat(
        p,
        "{\"clientIp\":", json_string(p, r->useragent_ip),
        ",\"timestamp\":", json_timestamp(p, r->request_time),
        ",\"requestLine\":{\"kind\":\"Parsed\"",
        ",\"raw\":", json_string(p, r->the_request),
        ",\"method\":", json_string(p, r->method),
        ",\"path\":", json_string(p, path),
        ",\"query\":", json_string(p, query),
        ",\"protocol\":", json_string(p, r->protocol),
        "},\"referer\":", json_string(p, apr_table_get(r->headers_in, "Referer")),
        ",\"userAgent\":", json_string(p, apr_table_get(r->headers_in, "User-Agent")),
        ",\"host\":", json_string(p, apr_table_get(r->headers_in, "Host")),
        ",\"tlsProtocol\":", json_string(p, tls),
        ",\"uniqueId\":", json_string(p, apr_table_get(r->subprocess_env, "UNIQUE_ID")),
        ",\"response\":null}",
        NULL);
}

/* ------------------------------------------------------------------------- */
/* Backend call                                                               */
/* ------------------------------------------------------------------------- */

/* errno of a failed call, never 0, so callers can rely on "non-zero means error" */
static int last_error(void)
{
    return errno != 0 ? errno : EIO;
}

/* Waits for the socket until the deadline. Returns 0 or an errno value. */
static int wait_socket(int fd, short events, apr_time_t deadline)
{
    for (;;) {
        apr_interval_time_t left = deadline - apr_time_now();
        if (left <= 0) {
            return ETIMEDOUT;
        }

        struct pollfd pfd = {.fd = fd, .events = events};
        int rc = poll(&pfd, 1, (int)((left + 999) / 1000));
        if (rc > 0) {
            return 0;
        }
        if (rc == 0) {
            return ETIMEDOUT;
        }
        if (errno != EINTR) {
            return last_error();
        }
    }
}

/* connects to the classification API socket */
static int connect_backend(const schiza_server_conf *conf, apr_time_t deadline, int *out_fd)
{
    int fd = socket(conf->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return last_error();
    }

    if (connect(fd, (const struct sockaddr *)&conf->addr, conf->addrlen) != 0) {
        int err = last_error();
        if (err != EINPROGRESS) {
            close(fd);
            return err;
        }

        err = wait_socket(fd, POLLOUT, deadline);
        if (err == 0) {
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
                err = last_error();
            }
        }
        if (err != 0) {
            close(fd);
            return err;
        }
    }

    *out_fd = fd;
    return 0;
}

static int send_all(int fd, const char *data, apr_size_t length, apr_time_t deadline)
{
    while (length > 0) {
        ssize_t sent = send(fd, data, length, MSG_NOSIGNAL);
        if (sent > 0) {
            data += sent;
            length -= (apr_size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int err = wait_socket(fd, POLLOUT, deadline);
            if (err != 0) {
                return err;
            }
            continue;
        }
        return sent < 0 ? last_error() : EPIPE;
    }
    return 0;
}

/* Reads the status line and headers (the body is not needed). */
static int receive_headers(int fd, char *buffer, apr_size_t size, apr_time_t deadline)
{
    apr_size_t used = 0;
    while (used < size - 1) {
        ssize_t received = recv(fd, buffer + used, size - 1 - used, 0);
        if (received > 0) {
            used += (apr_size_t)received;
            buffer[used] = '\0';
            if (strstr(buffer, "\r\n\r\n") != NULL) {
                return 0;
            }
            continue;
        }
        if (received == 0) {
            return used > 0 ? 0 : ECONNRESET;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int err = wait_socket(fd, POLLIN, deadline);
            if (err != 0) {
                return err;
            }
            continue;
        }
        return last_error();
    }
    buffer[used] = '\0';
    return 0;
}

/* Value of a response header, case-insensitive, or NULL */
static const char *find_header(apr_pool_t *p, const char *headers, const char *name)
{
    apr_size_t name_length = strlen(name);
    for (const char *line = strstr(headers, "\r\n"); line != NULL; line = strstr(line, "\r\n")) {
        line += 2;
        if (strncasecmp(line, name, name_length) == 0 && line[name_length] == ':') {
            const char *value = line + name_length + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            const char *end = strstr(value, "\r\n");
            return end != NULL ? apr_pstrmemdup(p, value, end - value) : apr_pstrdup(p, value);
        }
    }
    return NULL;
}

static schiza_verdict classify(request_rec *r, const schiza_server_conf *conf, const char **score)
{
    apr_time_t deadline = apr_time_now() + conf_timeout(conf);
    const char *body = build_request_json(r);
    const char *http_request = apr_psprintf(
        r->pool,
        "POST " SCHIZA_CLASSIFY_PATH " HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %" APR_SIZE_T_FMT "\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(body), body);

    int fd = -1;
    int err = connect_backend(conf, deadline, &fd);
    if (err != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, err, r, "schiza: cannot connect to %s, failing open", conf->backend);
        return SCHIZA_VERDICT_ERROR;
    }

    char *response = apr_palloc(r->pool, SCHIZA_RESPONSE_HEADER_LIMIT);
    err = send_all(fd, http_request, strlen(http_request), deadline);
    if (err == 0) {
        err = receive_headers(fd, response, SCHIZA_RESPONSE_HEADER_LIMIT, deadline);
    }
    close(fd);
    if (err != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, err, r, "schiza: no answer from %s, failing open", conf->backend);
        return SCHIZA_VERDICT_ERROR;
    }

    int status;
    if (sscanf(response, "HTTP/%*d.%*d %3d", &status) != 1) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "schiza: invalid HTTP response from %s, failing open",
                      conf->backend);
        return SCHIZA_VERDICT_ERROR;
    }

    *score = find_header(r->pool, response, "Schiza-Score");
    switch (status) {
    case HTTP_OK:
        return SCHIZA_VERDICT_ALLOW;
    case HTTP_FORBIDDEN:
        return SCHIZA_VERDICT_BLOCK;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "schiza: backend %s answered %d, failing open",
                      conf->backend, status);
        return SCHIZA_VERDICT_ERROR;
    }
}

/* ------------------------------------------------------------------------- */
/* Hook                                                                       */
/* ------------------------------------------------------------------------- */

static void set_verdict_note(request_rec *r, const char *verdict, const char *score)
{
    apr_table_setn(r->notes, SCHIZA_NOTE_VERDICT, verdict);
    if (score != NULL) {
        apr_table_setn(r->notes, SCHIZA_NOTE_SCORE, score);
    }
}

static int schiza_post_read_request(request_rec *r)
{
    const schiza_server_conf *conf = get_conf(r->server);
    if (conf->enabled != 1 || conf->addrlen == 0) {
        return DECLINED;
    }

    /* if not initial request (e.g. a redirect)
       get verdict for the original request */
    if (!ap_is_initial_req(r)) {
        if (r->prev != NULL) {
            const char *verdict = apr_table_get(r->prev->notes, SCHIZA_NOTE_VERDICT);
            if (verdict != NULL) {
                set_verdict_note(r, verdict, apr_table_get(r->prev->notes, SCHIZA_NOTE_SCORE));
            }
        }
        return DECLINED;
    }

    if (breaker_is_open(apr_time_now())) {
        set_verdict_note(r, "skipped", NULL);
        return DECLINED;
    }

    const char *score = NULL;
    switch (classify(r, conf, &score)) {
    case SCHIZA_VERDICT_ALLOW:
        breaker_record_success();
        set_verdict_note(r, "allow", score);
        return DECLINED;

    case SCHIZA_VERDICT_BLOCK:
        breaker_record_success();
        set_verdict_note(r, "block", score);
        if (conf_mode(conf) == SCHIZA_MODE_MONITOR) {
            return DECLINED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "schiza: blocked %s (score %s)",
                      ap_escape_logitem(r->pool, r->the_request), score != NULL ? score : "-");
        return HTTP_FORBIDDEN;

    case SCHIZA_VERDICT_ERROR:
    default:
        breaker_record_failure(r, conf);
        set_verdict_note(r, "error", NULL);
        return DECLINED; /* fail-open */
    }
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(schiza_post_read_request, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA schiza_module = {
    STANDARD20_MODULE_STUFF,
    NULL,               /* create per-dir config */
    NULL,               /* merge per-dir config */
    create_server_conf, /* create per-server config */
    merge_server_conf,  /* merge per-server config */
    schiza_cmds,        /* command table */
    register_hooks,     /* register hooks */
    0,                  /* flags */
};
