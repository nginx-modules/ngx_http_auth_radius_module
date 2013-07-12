#include <ngx_md5.h>
#include <assert.h>
#include <stdint.h>
#include "s_array.h"
#include <stddef.h>
#include "radius_client.h"

#define RADIUS_PKG_MAX  4096
#define RADIUS_STR_INIT( str ) .s = str, .len = strlen( str )

typedef struct radius_auth_t {
    unsigned char   d[ 16 ];
} radius_auth_t;

typedef struct radius_hdr_t {
    uint8_t         code;
    uint8_t         ident;
    uint16_t        len;
    radius_auth_t   auth;
} radius_hdr_t;

typedef struct radius_attr_hdr_t {
    uint8_t         type;
    uint8_t         len;
} radius_attr_hdr_t;

typedef struct radius_pkg_t {
    radius_hdr_t    hdr;
    unsigned char   attrs[ RADIUS_PKG_MAX - sizeof( radius_hdr_t ) ];
} radius_pkg_t;

typedef struct radius_pkg_builder_t {
    radius_pkg_t*   pkg;
    unsigned char*  pos;
} radius_pkg_builder_t;

static unsigned char
radius_random() {
    return (unsigned char)( random() & UCHAR_MAX );
}

typedef enum { 
    radius_attr_type_str,
    radius_attr_type_address,
    radius_attr_type_integer,
    radius_attr_type_time,
    radius_attr_type_chap_passwd,
} radius_attr_type_t;

typedef enum {
    radius_err_ok,
    radius_err_range,
    radius_err_mem,
} radius_error_t;

typedef struct radius_attr_chap_passwd_t {
    uint8_t chap_ident;
    unsigned char chap_data[ 16 ];
} radius_attr_chap_passwd_t;

typedef struct radius_attr_desc_t {
    radius_attr_type_t type;
    uint8_t            len_min;
    uint8_t            len_max;
} radius_attr_desc_t;

s_array_t* radius_servers = NULL;

#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCESS_CHALLENGE    4

#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_NAS_IDENTIFIER      32

#define RADIUS_SERVER_MAGIC_HDR     0x55AA00FF

#define RADIUS_ATTR_DESC_ITEM( t, lmin, lmax ) .type = t, .len_min =  lmin, .len_max = lmax

static radius_attr_desc_t attrs_desc[] = {
    [RADIUS_ATTR_USER_NAME]         { RADIUS_ATTR_DESC_ITEM( radius_attr_type_str, 1, 61 ) },
    [RADIUS_ATTR_USER_PASSWORD]     { RADIUS_ATTR_DESC_ITEM( radius_attr_type_str, 16, 128 ) },
    [RADIUS_ATTR_CHAP_PASSWORD]     { RADIUS_ATTR_DESC_ITEM( radius_attr_type_chap_passwd, sizeof( radius_attr_chap_passwd_t ), sizeof( radius_attr_chap_passwd_t ) ) },
    [RADIUS_ATTR_NAS_IP_ADDRESS]    { RADIUS_ATTR_DESC_ITEM( radius_attr_type_address, 4, 4 ) },
    [RADIUS_ATTR_NAS_PORT]          { RADIUS_ATTR_DESC_ITEM( radius_attr_type_address, 4, 4 ) },
    [RADIUS_ATTR_NAS_IDENTIFIER]    { RADIUS_ATTR_DESC_ITEM( radius_attr_type_str, 3, 64 ) },
};

radius_server_t*
radius_add_server( struct sockaddr* sockaddr, socklen_t socklen, radius_str_t* secret, radius_str_t* nas_identifier ) {

    if ( radius_servers == NULL ) {
        radius_servers = s_array_init( NULL, 20, sizeof( radius_server_t ) );
    }
    int s = socket( AF_INET, SOCK_DGRAM, 0 );
    if ( s == -1 )
        return NULL;

    radius_server_t* rs;
    rs = s_array_add( radius_servers, NULL );
    if ( rs == NULL )
        return NULL;

    rs->magic = RADIUS_SERVER_MAGIC_HDR;
    rs->id = radius_servers->size - 1;
    rs->s = s;
    rs->sockaddr = sockaddr;
    rs->socklen = socklen;
    rs->secret = *secret;
    rs->nas_identifier = *nas_identifier;

    memset( rs->req_queue, 0, sizeof( rs->req_queue ) );

    unsigned int i;
    radius_req_queue_node_t* qn;
    for( i = 1; i < sizeof( rs->req_queue ) / sizeof( rs->req_queue[0] ); i++ ) {
        qn = &rs->req_queue[ i ];
        qn->ident = i;
        rs->req_queue[ i - 1 ].next = qn;
    }
    rs->req_free_list = &rs->req_queue[ 0 ]; 
    rs->req_last_list = qn; 

    return rs;
}

radius_req_queue_node_t*
acquire_req_queue_node( radius_server_t* rs ) {
    radius_req_queue_node_t* n = rs->req_free_list;
    if ( n ) {
        rs->req_free_list = n->next;
        n->active = 1;
        if ( rs->req_free_list == NULL )
            rs->req_last_list = NULL;
    }
    return n;
}

radius_server_t*
get_server_by_req( radius_req_queue_node_t* n ) {
    // get rs by req node
    radius_server_t* rs;
    radius_req_queue_node_t* base = n - n->ident;
    rs = (radius_server_t*) ((char*) base - offsetof( radius_server_t, req_queue ));
    assert( rs->magic == RADIUS_SERVER_MAGIC_HDR );
    return rs;
}

void 
rlog( radius_server_t* rs, const char* fmt, ... ) {
    va_list  args;
    va_start( args, fmt );
    char buff[ 0x4000 ];
    vsnprintf( buff, sizeof( buff ), fmt, args );
    if ( rs->logger )
        rs->logger( rs->log, buff );
    va_end( args );
}

void
release_req_queue_node( radius_req_queue_node_t* n ) {

    radius_server_t* rs;
    rs = get_server_by_req( n );

    rlog( rs, "release_req_queue_node: 0x%lx, r: 0x%lx", n, n->data );

    n->active = 0;
    n->next = NULL;
    n->data = NULL;

    if ( rs->req_last_list ) {
        rs->req_last_list->next = n;
        rs->req_last_list = n;
        return;
    }

    assert( rs->req_free_list == rs->req_last_list && rs->req_free_list == NULL );
    rs->req_free_list = rs->req_last_list = n;

}

radius_req_queue_node_t*
radius_recv_request( radius_server_t* rs ) {

    struct sockaddr    sockaddr;
    socklen_t          socklen = sizeof( sockaddr );

    ssize_t len = recvfrom( rs->s, rs->process_buff, sizeof( rs->process_buff ), MSG_TRUNC, &sockaddr, &socklen );
    if ( len < 0 || len > (int) sizeof( rs->process_buff ) ) {
        rlog( rs, "radius_recv_request: error recvfrom" );
        return NULL;
    }

    radius_pkg_t* pkg = (radius_pkg_t*) rs->process_buff;
    uint16_t pkg_len = ntohs( pkg->hdr.len );
    if ( len != pkg_len ) {
        rlog( rs, "radius_recv_request: incorrect pkg len: %d | %d", len, pkg_len );
        return NULL;
    }

    radius_req_queue_node_t* n;
    n = &rs->req_queue[ pkg->hdr.ident ];
    if ( n->active == 0 ) {
        rlog( rs, "radius_recv_request: active = 0, 0x%lx, r: 0x%lx", n, n->data );
        return NULL;
    }

    ngx_md5_t ctx;
    ngx_md5_init( &ctx );

    char save_auth[ sizeof( pkg->hdr.auth ) ];
    unsigned char check[ sizeof( pkg->hdr.auth ) ];

    memcpy( save_auth, &pkg->hdr.auth, sizeof( save_auth ) );
    memcpy( &pkg->hdr.auth, &n->auth, sizeof( pkg->hdr.auth ) );
    ngx_md5_update( &ctx, pkg, len );
    ngx_md5_update( &ctx, rs->secret.s, rs->secret.len );
    ngx_md5_final( check, &ctx ); 

    if( 0 != memcmp( save_auth, check, sizeof( save_auth ) ) ) {
        rlog( rs, "radius_recv_request: incorrect auth, r: 0x%lx", n->data );
        return NULL;
    }

//    release_req_queue_node( n );
    n->accepted = pkg->hdr.code == RADIUS_CODE_ACCESS_ACCEPT;
    return n;

}


radius_req_queue_node_t*
radius_send_request( radius_req_queue_node_t* prev_req, radius_str_t* user, radius_str_t* passwd, void* log ) {

    radius_server_t* rss = radius_servers->data;
    radius_server_t* rs;
    
    if ( prev_req == NULL ) {
        rs = &rss[0];
    } else {
        rs = get_server_by_req( prev_req );
        rs = &rss[( rs->id + 1 ) % radius_servers->size ];
        release_req_queue_node( prev_req );
    }
    
    if ( !rs->log )
        rs->log = log;

    radius_req_queue_node_t* n;
    n = acquire_req_queue_node( rs );
    if ( n == NULL ) {
        // TODO try next server
        abort();
    }

    rlog( rs, "acquire_req_queue_node: 0x%lx, r: 0x%lx", n, n->data );
    
    int len = create_radius_req( rs->process_buff, sizeof( rs->process_buff ), 
        n->ident, user, passwd, &rs->secret, &rs->nas_identifier, n->auth );

    int rc = sendto( rs->s, rs->process_buff, len, 0, rs->sockaddr, rs->socklen );
    if ( rc == -1 ) {
        rlog( rs, "radius_send_request: sendto, r: 0x%lx, len: %u, error: %u", n->data,
            len, errno );
        release_req_queue_node( n );
        return NULL;
    }
    return n;
}

static void
init_radius_pkg( radius_pkg_builder_t* b, void* buff, int buff_size ) {
    b->pkg = buff;
    assert( buff_size == RADIUS_PKG_MAX ); // TODO
    b->pos = b->pkg->attrs;
}

static void
gen_authenticator( radius_auth_t* auth ) {
    uint8_t i;
    for( i = 0; i < sizeof( radius_auth_t ); i++ )
        auth->d[ i ] = radius_random();
}

static radius_error_t
check_str_attr_range_mem( radius_pkg_builder_t* b, int radius_attr_id, uint16_t len ) {

    if ( len < attrs_desc[ radius_attr_id ].len_min 
                    || len > attrs_desc[ radius_attr_id ].len_max )
        return radius_err_range;
    size_t remain = sizeof( b->pkg->attrs ) - ( b->pos - b->pkg->attrs );
    size_t str_attr_len_need = sizeof( radius_attr_hdr_t ) + len;
    if ( str_attr_len_need > remain )
        return radius_err_mem; 
    return radius_err_ok;

}

static radius_error_t
put_passwd_crypt( radius_pkg_builder_t* b, radius_str_t* secret, radius_str_t* passwd ) {

    uint8_t pwd_padded_len = 16 * ( 1 + passwd->len / 16 );
    radius_error_t rc = check_str_attr_range_mem( b, RADIUS_ATTR_USER_PASSWORD, pwd_padded_len );
    if ( rc != radius_err_ok )
        return rc;

    ngx_md5_t ctx;
    ngx_md5_t s_ctx;

    ngx_md5_init( &s_ctx );
    ngx_md5_update( &s_ctx, secret->s, secret->len );

    ctx = s_ctx;
    ngx_md5_update( &ctx, &b->pkg->hdr.auth, sizeof( b->pkg->hdr.auth ) );

    radius_attr_hdr_t* ah = (radius_attr_hdr_t*) b->pos;

    ah->type = RADIUS_ATTR_USER_PASSWORD;
    b->pos += sizeof( radius_attr_hdr_t );

    ngx_md5_final( b->pos, &ctx );

    uint8_t pwd_remain = passwd->len;
    uint8_t pwd_padded_remain = pwd_padded_len;
    unsigned char* p = passwd->s;
    unsigned char* c = b->pos;

    ah->len = sizeof( radius_attr_hdr_t ) + pwd_padded_remain;

    uint8_t i;
    for( ; pwd_padded_remain ; ) {
        for( i = 0; i < 16; i++ ) {
            *c++ ^= pwd_remain ? *p++ : 0;
            if ( pwd_remain )
                pwd_remain--;
        }
        ctx = s_ctx;
        pwd_padded_remain -= 16;
        if ( !pwd_padded_remain ) {
            b->pos += 16;
            break;
        }
        ngx_md5_update( &ctx, b->pos, c - b->pos );
        b->pos += 16;
        ngx_md5_final( b->pos, &ctx );
    }

    return radius_err_ok;
}

static int
put_str_attr( radius_pkg_builder_t* b, int radius_attr_id, radius_str_t* str ) {

    radius_error_t rc = check_str_attr_range_mem( b, radius_attr_id, str->len );
    if ( rc != radius_err_ok )
        return rc;
    
    radius_attr_hdr_t* ah = (radius_attr_hdr_t*) b->pos;
    ah->type = radius_attr_id;
    ah->len = str->len + sizeof( radius_attr_hdr_t );
    b->pos += sizeof( radius_attr_hdr_t );
    memcpy( b->pos, str->s, str->len );
    b->pos += str->len;
    return radius_err_ok;
}

#if 0
static radius_error_t
put_addr_attr( radius_pkg_builder_t* b, int radius_attr_id, uint32_t addr ) {

    size_t remain = sizeof( b->pkg->attrs ) - ( b->pos - b->pkg->attrs );
    size_t attr_len_need = sizeof( radius_attr_hdr_t ) + sizeof( addr );
    if ( attr_len_need > remain )
        return radius_err_mem;

    radius_attr_hdr_t* ah = (radius_attr_hdr_t*) b->pos;
    ah->type = radius_attr_id;
    ah->len = attr_len_need;
    b->pos += sizeof( radius_attr_hdr_t );
    uint32_t* v = (uint32_t*) b->pos;
    *v = addr;
    b->pos += sizeof( addr );

    return radius_err_ok; 
}
#endif

static radius_error_t
make_access_request_pkg( radius_pkg_builder_t* b, uint8_t ident, radius_str_t* secret, radius_str_t* user, radius_str_t* passwd, radius_str_t* nas_identifier ) {

    assert( b && user && passwd );
    b->pkg->hdr.code = RADIUS_CODE_ACCESS_REQUEST;
    b->pkg->hdr.ident = ident;

    radius_error_t rc;
    rc = put_str_attr( b, RADIUS_ATTR_USER_NAME, user );
    if ( rc != radius_err_ok )
        return rc;

    rc = put_passwd_crypt( b, secret, passwd );
    if ( rc != radius_err_ok )
        return rc;

    if ( nas_identifier->len >= 3 ) {
        rc = put_str_attr( b, RADIUS_ATTR_NAS_IDENTIFIER, nas_identifier );
        if ( rc != radius_err_ok )
            return rc;
    }

    return radius_err_ok;
}

static radius_error_t
update_pkg_len( radius_pkg_builder_t* b ) {
    uint16_t l = b->pos - (unsigned char*) &b->pkg->hdr;
    b->pkg->hdr.len = htons(l);
    return radius_err_ok;
}


uint16_t
create_radius_req( void* buff, int buff_size, uint8_t ident, radius_str_t* user, radius_str_t* passwd, radius_str_t* secret, radius_str_t* nas_identifier, unsigned char* auth ) {

    radius_pkg_builder_t b;

    init_radius_pkg( &b, buff, buff_size );
    gen_authenticator( &b.pkg->hdr.auth );
    if ( auth )
        memcpy( auth, &b.pkg->hdr.auth, sizeof( b.pkg->hdr.auth ) );
    make_access_request_pkg( &b, ident, secret, user, passwd, nas_identifier );

    update_pkg_len( &b );
   
    return b.pos - (unsigned char*) b.pkg;
}

void
check_pkg( void* buff, uint16_t len, radius_str_t* secret, unsigned char* auth ) {

    radius_pkg_t* pkg = (radius_pkg_t*) buff;
    uint16_t pkg_len = ntohs( pkg->hdr.len );
    if ( len != pkg_len )
        abort();

    ngx_md5_t ctx;
    ngx_md5_init( &ctx );

    ngx_md5_update( &ctx, &pkg->hdr, sizeof( pkg->hdr ) - sizeof( pkg->hdr.auth ) );
    ngx_md5_update( &ctx, auth, sizeof( pkg->hdr.auth ) );
    ngx_md5_update( &ctx, &pkg->attrs, len - sizeof( pkg->hdr ) );
    ngx_md5_update( &ctx, secret->s, secret->len );

    unsigned char res[16];
    ngx_md5_final( res, &ctx );

}
