#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ctype.h>
#include "radius_client.h"

typedef struct ngx_http_auth_radius_ctx_t {
    u_char                      digest[ 32 ];
    uint8_t                     attempts;
    radius_req_queue_node_t*    n;
    uint8_t                     accepted:1;
    uint8_t                     done:1;
} ngx_http_auth_radius_ctx_t;

typedef struct {
    ngx_str_t                realm;
    ngx_str_t                radius_cache;
    ngx_log_t*               log;
    ngx_uint_t               radius_timeout;
    ngx_uint_t               radius_attempts;
    radius_str_t             secret;
} ngx_http_auth_radius_main_conf_t;

static char* ngx_http_radius_set_auth_radius( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );
static char* ngx_http_radius_set_radius_server( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );
static char* ngx_http_radius_set_radius_timeout( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );
static char* ngx_http_radius_set_radius_attempts( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );
static ngx_int_t ngx_http_auth_radius_init(ngx_conf_t *cf);
static void * ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_auth_radius_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void * ngx_http_auth_radius_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_send_radius_request( ngx_http_request_t *r, radius_req_queue_node_t* prev_req );

static ngx_command_t  ngx_http_auth_radius_commands[] = {

    { ngx_string( "radius_server" ),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE23,
      ngx_http_radius_set_radius_server, 
      0,
      0, 
      NULL },

    { ngx_string( "radius_timeout" ),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_radius_set_radius_timeout,
      0,
      0,
      NULL }, 

    { ngx_string( "radius_attempts" ),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_radius_set_radius_attempts,
      0,
      0,
      NULL }, 

    { ngx_string( "radius_cache" ),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_auth_radius_main_conf_t, radius_cache ),
      NULL },

    { ngx_string( "auth_radius" ),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_radius_set_auth_radius,
      0,
      offsetof( ngx_http_auth_radius_main_conf_t, radius_timeout ),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_auth_radius_module_ctx = {
    NULL,                                               /* preconfiguration */
    ngx_http_auth_radius_init,                          /* postconfiguration */
    ngx_http_auth_radius_create_main_conf,              /* create main configuration */
    NULL,                                               /* init main configuration */
    NULL,                                               /* create server configuration */
    NULL,                                               /* merge server configuration */
    ngx_http_auth_radius_create_loc_conf,               /* create location configuration */
    ngx_http_auth_radius_merge_loc_conf,                /* merge location configuration */
};

ngx_module_t ngx_http_auth_radius_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_radius_module_ctx,       /* module context */
    ngx_http_auth_radius_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

#define RADIUS_STR_FROM_NGX_STR_INITIALIZER( ns ) .len = ns.len, .s = ns.data

static ngx_int_t
ngx_http_auth_radius_init_subrequest( ngx_http_request_t *r, ngx_str_t* url, ngx_str_t* args, ngx_http_post_subrequest_pt handler ) {

    ngx_http_request_t* sr;
    ngx_http_post_subrequest_t* ps;

    ps = ngx_palloc( r->pool, sizeof( ngx_http_post_subrequest_t ) );
    if ( ps == NULL ) {
        return NGX_ERROR;
    }

    ps->handler = handler;
    if ( ngx_http_subrequest( r, url, args, &sr, ps, 
            NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED
                ) != NGX_OK ) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t 
ngx_http_auth_radius_subrequest_mcset_done( ngx_http_request_t *r, void *data, ngx_int_t rc ) {
    return rc;
}

static ngx_int_t 
ngx_http_auth_radius_subrequest_mcget_done( ngx_http_request_t *r, void *data, ngx_int_t rc ) {

    if ( rc != NGX_OK ) {
        return rc;
    }

    ngx_http_request_t* mr = r->main;
    ngx_http_upstream_t* u;

    u = r->upstream;
    if ( u->buffer.pos == u->buffer.last ) { 
        // cache not found, send radius request
        ngx_send_radius_request( mr, NULL );
        return NGX_AGAIN;
    }

    // found
    ngx_str_t value;
    value.data = r->upstream->buffer.pos;
    value.len = r->upstream->buffer.last - r->upstream->buffer.pos;

    if ( value.len != 1 ) {
        ngx_send_radius_request( mr, NULL );
        return NGX_OK;
    }
    if ( *value.data != '1' ) {
        ngx_send_radius_request( mr, NULL );
        return NGX_OK;
    }

    if ( mr->connection->read->timer_set ) {
        mr->connection->read->timer_set = 0;
        ngx_del_timer( mr->connection->read );
    }

    ngx_http_auth_radius_ctx_t* ctx = ngx_http_get_module_ctx( mr, ngx_http_auth_radius_module );
    ctx->done = 1;
    ctx->accepted = 1;

    return NGX_OK;
}

void 
radius_logger( void* log, const char* fmt ) {
    ngx_uint_t level = 0;
    ngx_err_t err = 0;
    ngx_log_error_core( level, log, err, fmt, NULL );
}

void 
radius_read_handler( ngx_event_t* rev ) {

    ngx_connection_t* c = rev->data;

    radius_server_t* rs = c->data;

    if ( rev->timedout ) {
        rev->timedout = 0;
    }

    if ( rev->timer_set ) {
        ngx_del_timer( rev );
    }

    radius_req_queue_node_t* n;
    n = radius_recv_request( rs );
    if ( n == NULL ) {
        // not found TODO
        ngx_log_error( NGX_LOG_ERR, rev->log, 0, "radius_read_handler: request not found" );
        return;
    }

    ngx_http_request_t *r = n->data;
    ngx_log_error( NGX_LOG_ERR, rev->log, 0, "radius_read_handler: rs: %d, 0x%xl, 0x%xl, id: %d, acc: %d", rs->id, r, n, n->ident, n->accepted );

    if ( r->connection->data != r ) {
        ngx_log_error( NGX_LOG_ERR, rev->log, 0, "radius_read_handler: GONE" );
        return;
    }

    ngx_http_auth_radius_ctx_t* ctx = ngx_http_get_module_ctx( r, ngx_http_auth_radius_module );
    if ( ctx == NULL || ctx->n != n ) {
        ngx_log_error( NGX_LOG_ERR, rev->log, 0, "radius_read_handler: GONE 1" );
        return;
    }

    if ( r->connection->read->timer_set ) {
        r->connection->read->timer_set = 0;
        ngx_del_timer( r->connection->read );
    }

    ctx->done = 1;
    ctx->accepted = n->accepted;

    ngx_http_auth_radius_main_conf_t* conf = ngx_http_get_module_loc_conf( r, ngx_http_auth_radius_module );
    ngx_str_t args;
    ngx_str_t key;
    key.data = ctx->digest;
    key.len = sizeof( ctx->digest );
    args.len = sizeof( "o=set&v=X&k=" ) - 1 + key.len; // TODO
    args.data = ngx_palloc( r->pool, args.len );
    u_char* e = ngx_snprintf( args.data, args.len, "o=set&v=%d&k=%V", n->accepted, &key );
    args.len = e - args.data;
    int rc = ngx_http_auth_radius_init_subrequest( r, &conf->radius_cache, &args, ngx_http_auth_radius_subrequest_mcset_done );
    if ( rc != NGX_OK )
        abort(); // TODO
    ngx_post_event( r->connection->write, &ngx_posted_events );

    release_req_queue_node( n );

}


static ngx_int_t
ngx_send_radius_request( ngx_http_request_t *r, radius_req_queue_node_t* prev_req ) {

    ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request 0x%xl", r );
    ngx_http_auth_radius_main_conf_t* conf = ngx_http_get_module_main_conf( r, ngx_http_auth_radius_module );

    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_get_module_loc_conf( r, ngx_http_core_module );

    ngx_http_auth_radius_ctx_t* ctx = ngx_http_get_module_ctx( r, ngx_http_auth_radius_module );
    if ( ctx == NULL )
        abort(); // TODO

    radius_str_t user = { RADIUS_STR_FROM_NGX_STR_INITIALIZER( r->headers_in.user ) };
    radius_str_t passwd = { RADIUS_STR_FROM_NGX_STR_INITIALIZER( r->headers_in.passwd ) };

    radius_req_queue_node_t* n;
    n = radius_send_request( prev_req, &user, &passwd, clcf->error_log );
    if ( n == NULL ) {
        abort(); // TODO
    }

    ngx_http_auth_radius_main_conf_t* lconf = ngx_http_get_module_loc_conf( r, ngx_http_auth_radius_module );
    ngx_add_timer( r->connection->read, lconf->radius_timeout ); 

    radius_server_t* rs;
    rs = get_server_by_req( n );
    ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request rs: %d, assign 0x%xl to 0x%xl, id: %d", rs->id, r, n, n->ident );

    n->data = r;
    ctx->n = n;

    ngx_connection_t* c = rs->data;
    ngx_event_t* rev;

    if ( c == NULL ) {

        c = ngx_get_connection( rs->s, conf->log );
        if ( c == NULL ) {
            ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request: ngx_get_connection" );
            if (ngx_close_socket( rs->s ) == -1)
                ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request: ngx_close_socket" );
            return NGX_ERROR;
        }

        if ( ngx_nonblocking( rs->s ) == -1 ) {
            ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request: ngx_nonblocking" );
            ngx_free_connection( c );
            if (ngx_close_socket( rs->s ) == -1)
                ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request: ngx_close_socket" );
            return NGX_ERROR;
        }

        rs->data = c;
        c->data = rs;

        rev = c->read;
        rev->handler = radius_read_handler;
        rev->log = clcf->error_log;
        rs->log = clcf->error_log;

        if ( ngx_add_event( rev, NGX_READ_EVENT, NGX_LEVEL_EVENT ) != NGX_OK ) {
            ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "ngx_send_radius_request: ngx_add_event" );
            return NGX_ERROR;
        }

        c->number = ngx_atomic_fetch_add( ngx_connection_counter, 1 );
    }
    return NGX_OK;
}

void 
http_req_read_handler( ngx_http_request_t *r ) {

    ngx_http_auth_radius_ctx_t* ctx = ngx_http_get_module_ctx( r, ngx_http_auth_radius_module );
    
    ngx_connection_t* c = r->connection;
    ngx_event_t* rev = c->read;

    if ( rev->timedout ) {
        rev->timedout = 0;
        ctx->attempts--;
        ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "http_req_read_handler: timeout 0x%xd, attempt: %d", r, ctx->attempts );
        if ( ctx->attempts == 0 ) {
            ctx->done = 1;
            ngx_post_event( r->connection->write, &ngx_posted_events );
            return;
        }
        ngx_send_radius_request( r, ctx->n );
        return;
    }

    u_char buf[ 1 ];
    int n = recv( c->fd, buf, sizeof( buf ), MSG_PEEK );

    if ( n == 0 ) {
        rev->eof = 1;
        c->error = 1;
        if ( ctx->n != NULL ) {
            ctx->n->active = 0;
        } 
        ngx_http_finalize_request( r, 0 );
        return;
    } else if (n == -1) {
        int err = ngx_socket_errno;
        if ( err != NGX_EAGAIN ) {
            rev->eof = 1;
            c->error = 1;
        }
        ngx_http_finalize_request(r, 0);
        return;
    }

    ngx_http_block_reading( r );
}

void
calc_req_digest( ngx_http_request_t* r, radius_str_t* secret, u_char* digest ) {

    ngx_md5_t md5; 
    ngx_md5_init( &md5 ); 
    ngx_md5_update( &md5, secret->s, secret->len ); 
    ngx_md5_update( &md5, r->headers_in.user.data, r->headers_in.user.len ); 
    ngx_md5_update( &md5, r->headers_in.passwd.data, r->headers_in.passwd.len ); 

    u_char d[ 16 ];
    ngx_md5_final( d, &md5 ); 

    ngx_hex_dump( digest, d, sizeof( d ) );

}

static ngx_int_t
ngx_http_auth_radius_handler( ngx_http_request_t *r )
{
    ngx_http_auth_radius_ctx_t* ctx;
    ctx = ngx_http_get_module_ctx( r, ngx_http_auth_radius_module );

    ngx_http_auth_radius_main_conf_t* conf = ngx_http_get_module_loc_conf( r, ngx_http_auth_radius_module );
    if ( conf->realm.data == NULL || conf->realm.len == 0 )
        return NGX_OK;

    ngx_int_t rc = ngx_http_auth_basic_user( r );

    if ( rc == NGX_ERROR )
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if ( rc == NGX_DECLINED || ( ctx && ctx->done && ctx->accepted == 0 ) ) {
        r->headers_out.www_authenticate = ngx_list_push( &r->headers_out.headers );

        if ( r->headers_out.www_authenticate == NULL ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.www_authenticate->hash = 1;
        r->headers_out.www_authenticate->key.len = sizeof( "WWW-Authenticate" ) - 1;
        r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";

        ngx_int_t realm_len = sizeof( "Basic realm=\"\"" ) + conf->realm.len;    

        ngx_buf_t* b = ngx_create_temp_buf( r->pool, realm_len );
        ngx_snprintf( b->pos, realm_len, "Basic realm=\"%V\"", &conf->realm );

        r->headers_out.www_authenticate->value.data = b->pos;
        r->headers_out.www_authenticate->value.len = realm_len - 1;
        return NGX_HTTP_UNAUTHORIZED;
    }

    if ( ctx == NULL ) {
        ctx = ngx_pcalloc( r->pool, sizeof( *ctx ) );
        if ( ctx == NULL ) {
            // TODO log
            return NGX_ERROR;
        }
        ctx->attempts = conf->radius_attempts;
        ctx->done = 0;
        ctx->accepted = 0;
        ngx_http_set_ctx( r, ctx, ngx_http_auth_radius_module );
        r->read_event_handler = http_req_read_handler;

        ngx_str_t args;
        ngx_str_t key;

        calc_req_digest( r, &conf->secret, ctx->digest );
        key.data = ctx->digest;
        key.len = sizeof( ctx->digest );
        args.len = sizeof( "o=get&k=" ) - 1 + key.len; // TODO
        args.data = ngx_palloc( r->pool, args.len );
        u_char* e = ngx_snprintf( args.data, args.len, "o=get&k=%V", &key );
        args.len = e - args.data;

        rc = ngx_http_auth_radius_init_subrequest( r, &conf->radius_cache, &args, ngx_http_auth_radius_subrequest_mcget_done );

        return NGX_AGAIN;
    }

    if ( ctx->done == 0 ) {
        return NGX_AGAIN;
    }

    ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "GRANTED 0x%xl", r );
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_radius_init( ngx_conf_t *cf )
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf( cf, ngx_http_core_module );

    //h = ngx_array_push( &cmcf->phases[ NGX_HTTP_PREACCESS_PHASE ].handlers );
    h = ngx_array_push( &cmcf->phases[ NGX_HTTP_ACCESS_PHASE ].handlers );
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_radius_handler; 

    return NGX_OK;
}

static char *
ngx_http_auth_radius_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child ) {

    ngx_http_auth_radius_main_conf_t *prev = parent;
    ngx_http_auth_radius_main_conf_t *conf = child;

    ngx_conf_merge_str_value( conf->realm, prev->realm, "" );
    ngx_conf_merge_str_value( conf->radius_cache, prev->radius_cache, "" );

    ngx_conf_merge_msec_value( conf->radius_timeout, prev->radius_timeout, 60000 );
    ngx_conf_merge_uint_value( conf->radius_attempts, prev->radius_attempts, 3 );

    return NGX_CONF_OK;

}

static void *
ngx_http_auth_radius_create_loc_conf( ngx_conf_t *cf )
{
    ngx_http_auth_radius_main_conf_t* mconf;
    mconf = ngx_pcalloc( cf->pool, sizeof( ngx_http_auth_radius_main_conf_t ) );
    if ( mconf == NULL ) {
        return NGX_CONF_ERROR;
    }
    mconf->realm.data = NULL;
    mconf->log = NGX_CONF_UNSET_PTR;
    mconf->radius_attempts = NGX_CONF_UNSET;
    mconf->radius_timeout = NGX_CONF_UNSET_MSEC;
    return mconf;
}

static void *
ngx_http_auth_radius_create_main_conf( ngx_conf_t *cf )
{
    ngx_http_auth_radius_main_conf_t* mconf;

    mconf = ngx_pcalloc( cf->pool, sizeof( ngx_http_auth_radius_main_conf_t ) );
    if ( mconf == NULL ) {
        return NGX_CONF_ERROR;
    }
    mconf->realm.data = NULL;
    mconf->log = NGX_CONF_UNSET_PTR;
    mconf->radius_attempts = NGX_CONF_UNSET;
    mconf->radius_timeout = NGX_CONF_UNSET_MSEC;
    return mconf;
}

static char*
ngx_http_radius_set_auth_radius( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) {

    ngx_str_t* value = cf->args->elts;

    if ( ngx_strncasecmp( (unsigned char*) "off", value[1].data, 3 ) == 0 ) 
        return NGX_CONF_OK;

    ngx_http_auth_radius_main_conf_t* mconf = ngx_http_conf_get_module_loc_conf( cf, ngx_http_auth_radius_module );
    mconf->realm = value[1];

    return NGX_CONF_OK;
}

static char* 
ngx_http_radius_set_radius_timeout( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) {
    ngx_str_t* value = cf->args->elts;
    ngx_http_auth_radius_main_conf_t* mconf = ngx_http_conf_get_module_main_conf( cf, ngx_http_auth_radius_module );
    mconf->radius_timeout = ngx_atoi( value[1].data, value[1].len );
    return NGX_CONF_OK;
}

static char* 
ngx_http_radius_set_radius_attempts( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) {
    ngx_str_t* value = cf->args->elts;
    ngx_http_auth_radius_main_conf_t* mconf = ngx_http_conf_get_module_main_conf( cf, ngx_http_auth_radius_module );
    mconf->radius_attempts = ngx_atoi( value[1].data, value[1].len );
    return NGX_CONF_OK;
}

static char* 
ngx_http_radius_set_radius_server( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) {

    ngx_http_auth_radius_main_conf_t* mconf = ngx_http_conf_get_module_main_conf( cf, ngx_http_auth_radius_module );

    ngx_str_t* value = cf->args->elts;
    if ( cf->args->nelts != 3 && cf->args->nelts != 4 )
        return "invalid value";

    ngx_url_t u;
    ngx_memzero( &u, sizeof(ngx_url_t) );
    u.url = value[1];
    u.uri_part = 1;
    u.one_addr = 1;
    u.default_port = RADIUS_DEFAULT_PORT;
    if ( ngx_parse_url( cf->pool, &u ) != NGX_OK ) {
        if ( u.err ) {
            ngx_conf_log_error( NGX_LOG_EMERG, cf, 0,
                            "%s ngx_http_radius_set_radius_server \"%V\"", u.err, &u.url );
        }
        return "invalid address";
    }

    radius_str_t secret;
    secret.s = value[2].data;
    secret.len = value[2].len;

    mconf->secret.s = secret.s;
    mconf->secret.len = secret.len;

    radius_str_t nas_identifier;
    nas_identifier.s = NULL;
    nas_identifier.len = 0;

    if ( cf->args->nelts == 4 ) {
        nas_identifier.s = value[3].data;
        nas_identifier.len = value[3].len;
    }

    radius_server_t* rs;
    rs = radius_add_server( u.addrs[0].sockaddr, u.addrs[0].socklen, &secret, &nas_identifier );
    rs->logger = radius_logger;

    return NGX_CONF_OK;
}

