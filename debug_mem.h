#ifndef __DEBUG_MEM_H__
#define __DEBUG_MEM_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>


#define _DEBUG_MEMINFO
#ifdef _DEBUG_MEMINFO
	#ifndef __file__
		#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
	#endif

	#define dbg_malloc(sz)        _media_malloc(__file__, __LINE__, __func__ , sz)
	#define dbg_calloc(nmb, sz)   _media_calloc(__file__, __LINE__, __func__ , nmb, sz)
	#define dbg_realloc(ptr, sz)  _media_realloc(__file__, __LINE__, __func__ , ptr, sz)
	#define dbg_free(blk)         _media_free(__file__, __LINE__, __func__ , blk)
	#define dbg_strdup(ptr)       _media_strdup(__file__, __LINE__, __func__ , ptr)
	#define dbg_strndup(ptr, sz)  _media_strndup(__file__, __LINE__, __func__ , ptr, sz)

	#define m_dbg(fmt,args...) \
			do{\
				fprintf(stderr, "\e[2;37m>[%s %5d:%s]\e[m "fmt, __file__, __LINE__, __func__, ##args);\
			}while(0)
#else
	#define dbg_malloc(sz)        malloc(sz)
	#define dbg_calloc(nmb, sz)   calloc(nmb, sz)
	#define dbg_realloc(ptr, sz)  realloc(ptr, sz)
	#define dbg_free(blk)         free( (blk) )
	#define dbg_strdup(ptr)       strdup( (ptr) )
	#define dbg_strndup(ptr, sz)  strndup( (ptr), (sz) )

	#define m_dbg(fmt,args...)  ((void)0)
#endif

#define _ENABLE_VERVOSE (0) //(1)

/*
 * P U B L I C    A P I s
 *
 */
void media_mem_init(char *tag, int KbytesSize);
void media_mem_delete(char *tag);
unsigned int media_mem_stats(size_t *count);

void _media_free(const char *file, const int line, const char *func, void *blk);
void *_media_malloc(const char *file, const int line, const char *func, size_t sz);
void *_media_calloc(const char *file, const int line, const char *func, size_t nmb, size_t sz);
void *_media_realloc(const char *file, const int line, const char *func, void *ptr, size_t sz);
unsigned char *_media_strdup(const char *file, const int line, const char *func, const char *ptr);
unsigned char *_media_strndup(const char *file, const int line, const char *func, const char *ptr, size_t sz);


#endif // __DEBUG_MEM_H__
