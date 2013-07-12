#ifndef S_ARRAY_H
#define S_ARRAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct s_array_t
{
    void* data;
    uint32_t max_size;
    uint32_t size;
    uint32_t elem_size;
} 
s_array_t;

struct s_array_t* 
s_array_init( struct s_array_t* array, int32_t init_size, int32_t elem_size ); 

void* 
s_array_get( struct s_array_t* array, uint32_t ix );

void*
s_array_add_n( struct s_array_t* array, void* elem, int n );

void*
s_array_add( struct s_array_t* array, void* elem );

void 
s_array_free( struct s_array_t* array, void (*clear_func)(void*) );

#ifdef __cplusplus
}
#endif

#endif
