#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

static ngx_str_t MC_STR_STORED      = ngx_string( "STORED\r\n" );
static ngx_str_t MC_STR_END         = ngx_string( "END\r\n" );
static ngx_str_t MC_STR_VALUE       = ngx_string( "VALUE " );
static ngx_str_t ngx_mcset_op       = ngx_string( "mcset_op" );
static ngx_str_t ngx_mcset_key      = ngx_string( "mcset_key" );
static ngx_str_t ngx_mcset_val      = ngx_string( "mcset_val" );

typedef struct {
    time_t                      mc_expiration;
    ngx_http_upstream_conf_t    upstream;
    ngx_int_t                   op_index;
    ngx_int_t                   key_index;
    ngx_int_t                   val_index;
} ngx_http_mcset_module_conf_t;

typedef enum {
    MCSET_STATE_MC_GET,
    MCSET_STATE_MC_SET,
} mcset_module_state_t;

typedef struct {
    mcset_module_state_t    state;
    ngx_str_t               cache_id;
    ngx_http_request_t*     r;
} ngx_mcset_module_ctx_t;

static ngx_int_t ngx_http_mcset_module_init( ngx_conf_t *cf );
static char* ngx_conf_mcset_set_pass( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );
static void* ngx_http_mcset_module_create_loc_conf( ngx_conf_t *cf );
static char* ngx_http_mcset_module_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child );
static ngx_int_t ngx_http_mcset_module_init_cache_request( ngx_http_request_t *r );
static ngx_int_t ngx_http_mcset_module_cache_handler( ngx_http_request_t *r );

static ngx_command_t ngx_http_mcset_module_commands[] = {

   { ngx_string( "mcset_expiration" ),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof( ngx_http_mcset_module_conf_t, mc_expiration ),
     NULL },

   { ngx_string( "mcset_pass" ),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_mcset_set_pass,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL },

   { ngx_string( "mcset_connect_timeout" ),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof( ngx_http_mcset_module_conf_t, upstream.connect_timeout ),
     NULL },

   { ngx_string( "mcset_send_timeout" ),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof( ngx_http_mcset_module_conf_t, upstream.send_timeout ),
     NULL },

   { ngx_string( "mcset_read_timeout" ),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof( ngx_http_mcset_module_conf_t, upstream.read_timeout ),
     NULL },

     ngx_null_command
};

static ngx_http_module_t ngx_http_mcset_module_ctx = {
    NULL,                                               /* preconfiguration */
    ngx_http_mcset_module_init,                           /* postconfiguration */
    NULL,                                               /* create main configuration */
    NULL,                                               /* init main configuration */
    NULL,                                               /* create server configuration */
    NULL,                                               /* merge server configuration */
    ngx_http_mcset_module_create_loc_conf,                /* create location configuration */
    ngx_http_mcset_module_merge_loc_conf,                 /* merge location configuration */
};

ngx_module_t ngx_http_mcset_module = {
    NGX_MODULE_V1,
    &ngx_http_mcset_module_ctx,               /* module context */
    ngx_http_mcset_module_commands,           /* module directives */
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

static void* 
ngx_http_mcset_module_create_loc_conf( ngx_conf_t *cf ) {
    ngx_http_mcset_module_conf_t* mscf;

    mscf = ngx_pcalloc( cf->pool, sizeof( ngx_http_mcset_module_conf_t ) );
    if ( mscf == NULL ) {
        return NULL;
    }
    mscf->mc_expiration = NGX_CONF_UNSET;
    mscf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    mscf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    mscf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    mscf->upstream.buffer_size = NGX_CONF_UNSET;

    return mscf;
}

static ngx_int_t 
ngx_http_mcset_module_init( ngx_conf_t *cf ) {
    return NGX_OK;
}

static char* 
ngx_http_mcset_module_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child ) {

    ngx_http_mcset_module_conf_t* prev = parent;
    ngx_http_mcset_module_conf_t* conf = child;

    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf( cf, ngx_http_core_module );

    ngx_conf_merge_msec_value( conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000 );
    ngx_conf_merge_msec_value( conf->upstream.send_timeout, prev->upstream.send_timeout, 60000 );
    ngx_conf_merge_msec_value( conf->upstream.read_timeout, prev->upstream.read_timeout, 60000 );
    ngx_conf_merge_msec_value( conf->upstream.buffer_size, prev->upstream.buffer_size, 1024 );

    if ( conf->upstream.upstream == NULL ) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if ( conf->upstream.upstream != NULL ) { 
        clcf->handler = ngx_http_mcset_module_cache_handler;
    }

    return NGX_CONF_OK;
}



static char* 
ngx_conf_mcset_set_pass( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) {
    
    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_mcset_module_conf_t* mscf;

    mscf = conf;

    if ( mscf->upstream.upstream ) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero( &u, sizeof( ngx_url_t ) );

    u.url = value[1];
    u.no_resolve = 1;

    mscf->upstream.upstream = ngx_http_upstream_add( cf, &u, 0 );
    if ( mscf->upstream.upstream == NULL ) {
        return NGX_CONF_ERROR;
    }

    mscf->key_index = ngx_http_get_variable_index( cf, &ngx_mcset_key );
    if ( mscf->key_index == NGX_ERROR ) {
        return NGX_CONF_ERROR;
    }

    mscf->val_index = ngx_http_get_variable_index( cf, &ngx_mcset_val );
    if ( mscf->val_index == NGX_ERROR ) {
        return NGX_CONF_ERROR;
    }

    mscf->op_index = ngx_http_get_variable_index( cf, &ngx_mcset_op );
    if ( mscf->op_index == NGX_ERROR ) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

}

static ngx_int_t
ngx_http_mcset_cache_create_request( ngx_http_request_t *r ) {

    size_t len;
    ngx_buf_t* b;
    ngx_chain_t* cl;
    ngx_mcset_module_ctx_t* ctx;
    ngx_http_mcset_module_conf_t* mscf;
    ngx_http_variable_value_t* vop;
    ngx_http_variable_value_t* vval;
    ngx_http_variable_value_t* vkey;

    mscf = ngx_http_get_module_loc_conf( r, ngx_http_mcset_module );
    ctx = ngx_http_get_module_ctx( r, ngx_http_mcset_module );
    if ( ctx == NULL )
        return NGX_ERROR;

    vkey = ngx_http_get_indexed_variable( r, mscf->key_index );
    if ( vkey == NULL || vkey->not_found || vkey->len == 0 ) {
        ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "the \"key\" variable is not set" );
        return NGX_ERROR;
    }

    vop = ngx_http_get_indexed_variable( r, mscf->op_index );
    if ( vop == NULL || vop->not_found || vop->len == 0 ) {
        ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "the \"op\" variable is not set" );
        return NGX_ERROR;
    }

    if ( vop->len != 3 )
        return NGX_ERROR;

    u_char* o = vop->data;
    if ( *(o+1) != 'e' || *(o+2) != 't' )
        return NGX_ERROR;
    
    if ( *o == 'g' ) {
        ctx->state = MCSET_STATE_MC_GET;
    } else if ( *o == 's' ) {
        ctx->state = MCSET_STATE_MC_SET;
    } else {
        return NGX_ERROR;
    }

    ctx->cache_id.data = vkey->data;
    ctx->cache_id.len = vkey->len;

    if ( ctx->state == MCSET_STATE_MC_GET ) {

        len = sizeof( "get " ) - 1 
            + vkey->len 
            + sizeof( CRLF ) - 1;

        b = ngx_create_temp_buf( r->pool, len );
        if ( b == NULL ) {
            return NGX_ERROR;
        }

        b->last = ngx_snprintf( b->last, len, "get %v\r\n", vkey );

    } else if ( ctx->state == MCSET_STATE_MC_SET ) {

        vval = ngx_http_get_indexed_variable( r, mscf->val_index );
        if ( vval == NULL || vval->not_found || vval->len == 0 ) {
            ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "the \"val\" variable is not set" );
            return NGX_ERROR;
        }

        ngx_uint_t expiration = mscf->mc_expiration;
        len = sizeof( "set " ) - 1
            + vkey->len +
            + 2 // space + flags
            + 1 + NGX_ATOMIC_T_LEN // timeout
            + 1 + NGX_ATOMIC_T_LEN // vlen
            + 2 // CRLF
            + vval->len
            + 2 // CRLF
            ;

        b = ngx_create_temp_buf( r->pool, len );
        if ( b == NULL ) {
            return NGX_ERROR;
        }

        b->last = ngx_snprintf( b->last, len, "set %v 0 %d %d\r\n%v\r\n", 
            vkey, expiration, vval->len, vval );
        
    } else
        abort();

    cl = ngx_alloc_chain_link( r->pool );
    if ( cl == NULL ) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mcset_cache_reinit_request( ngx_http_request_t *r ) {
    return NGX_OK;
}

void
ngx_http_mcset_cache_abort_request( ngx_http_request_t *r ) {
    abort();
}

void
ngx_http_mcset_cache_finalize_request( ngx_http_request_t *r, ngx_int_t rc ) {

//    ngx_http_mcset_module_conf_t*     mscf;
//    mscf = ngx_http_get_module_loc_conf( r, ngx_http_mcset_module );
    r->subrequest_in_memory = 0;
//    r->count--;
    return;
}

static ngx_int_t
ngx_http_mcset_module_filter_init( void *data ) {
    return NGX_OK;
}

static ngx_int_t
ngx_http_mcset_module_filter( void *data, ssize_t bytes ) {
    ngx_mcset_module_ctx_t* ctx = data;
    ngx_http_request_t* r = ctx->r;
    if ( ctx->state == MCSET_STATE_MC_GET )
        r->upstream->buffer.last = r->upstream->buffer.pos + bytes;
    return NGX_OK;
}

static ngx_int_t
ngx_http_mcset_cache_parse_header( ngx_http_request_t *r, ngx_str_t* v ) {

    ngx_http_upstream_t* u;
    u_char* b;
    u_char* e;
    ngx_mcset_module_ctx_t* ctx;

    u = r->upstream;
    b = u->buffer.pos;
    e = u->buffer.last;

    ctx = ngx_http_get_module_ctx( r, ngx_http_mcset_module );
    if ( ctx->state == MCSET_STATE_MC_SET ) {
        if ( e - b != (ssize_t) MC_STR_STORED.len ||
            ngx_strncmp( b, MC_STR_STORED.data, MC_STR_STORED.len ) != 0 )
                return NGX_ERROR;
        return NGX_OK;
    }

    if ( e - b < (ssize_t) MC_STR_END.len )
        return NGX_AGAIN;

    if ( ngx_strncmp( e - MC_STR_END.len, MC_STR_END.data, MC_STR_END.len ) != 0 )
        return NGX_AGAIN;

    e -= MC_STR_END.len;
    if ( e == b ) {
        v->len = 0;
        u->buffer.last = u->buffer.pos;
        return NGX_OK; // not found
    }

    e -= 2; // CRLF
    if ( e - b < (ssize_t) MC_STR_VALUE.len || ngx_strncmp( b, MC_STR_VALUE.data, MC_STR_VALUE.len ) != 0 )
        return NGX_ERROR;

    b += MC_STR_VALUE.len;

    if ( e - b < (ssize_t) ctx->cache_id.len
            || ngx_strncmp( b, ctx->cache_id.data, ctx->cache_id.len ) != 0 )
        return NGX_ERROR;
    
    b += ctx->cache_id.len;

    uint8_t s = 0;
    for( ; b <= e && s != 4; b++ ) {
        switch( s ) {
            case 0: // space before flags
                if ( *b != ' ' )
                    return NGX_ERROR;
                s = 1;
                break;
            case 1: // flags
                if ( *b != ' ' )
                    continue;
                s = 2;
                break;
            case 2: // len
                if ( *b != '\r' )
                    continue;
                s = 3;
                break;
            case 3:
                if ( *b != '\n' )
                    return NGX_ERROR;
                s = 4;
                break;
        }
    }
  
    v->data = b;
    v->len = e - b;
    u->buffer.pos = b;
    u->buffer.last = e;
    return NGX_OK;
}

static ngx_int_t
ngx_http_mcset_cache_process_header( ngx_http_request_t *r ) {

    ngx_int_t  rc;
    // ctx = ngx_http_get_module_ctx( r, ngx_http_mcset_module );
    ngx_str_t v;

    rc = ngx_http_mcset_cache_parse_header( r, &v );
    if ( rc != NGX_OK )
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;

    // TODO
    r->upstream->headers_in.status_n = 200;
    r->upstream->state->status = 200;
    r->upstream->headers_in.content_length_n = 0; 
    r->upstream->keepalive = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mcset_module_cache_handler( ngx_http_request_t *r ) {
    int rc = ngx_http_mcset_module_init_cache_request( r );
    if ( rc != NGX_OK )
        return rc; 
    return NGX_DONE;
}

static ngx_int_t
ngx_http_mcset_module_init_cache_request( ngx_http_request_t *r ) {

    ngx_http_mcset_module_conf_t*     mscf;
    ngx_http_upstream_t             *u;
    ngx_mcset_module_ctx_t* ctx;

    mscf = ngx_http_get_module_loc_conf( r, ngx_http_mcset_module );
    ctx = ngx_http_get_module_ctx( r, ngx_http_mcset_module );

    if ( ctx == NULL ) {
        ctx = ngx_pcalloc( r->pool, sizeof( ngx_mcset_module_ctx_t ) );
        if ( ctx == NULL ) {
            return NGX_ERROR;
        }
        ctx->cache_id.len = 32;
        ctx->cache_id.data = ngx_pcalloc( r->pool, ctx->cache_id.len );
        ctx->r = r;
        ngx_http_set_ctx( r, ctx, ngx_http_mcset_module );
    }

    if ( ngx_http_upstream_create( r ) != NGX_OK ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;
    ngx_str_set( &u->schema, "memcached://" );
    u->conf = &mscf->upstream;
    u->create_request = ngx_http_mcset_cache_create_request;
    u->reinit_request = ngx_http_mcset_cache_reinit_request;
    u->process_header = ngx_http_mcset_cache_process_header;
    u->abort_request = ngx_http_mcset_cache_abort_request;
    u->finalize_request = ngx_http_mcset_cache_finalize_request;

    u->input_filter_init = ngx_http_mcset_module_filter_init;
    u->input_filter = ngx_http_mcset_module_filter;
    u->input_filter_ctx = ctx;

    r->subrequest_in_memory = 1;
    r->main->count++;
 
    ngx_http_upstream_init( r );
    return NGX_OK;
}

