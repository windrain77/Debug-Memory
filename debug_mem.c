#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "debug_mem.h"

/* 
 * T Y P E S 
 *
 */
#define FILE_NAME_MAX 32 //FILENAME_MAX /*4096*/
#define FUNC_NAME_MAX 32 //NAME_MAX /*255*/
typedef struct __attribute__((packed)) __media_sysmem_info{
	unsigned char file[FILE_NAME_MAX];  /* file.. */
	unsigned char func[FUNC_NAME_MAX];  /* func.. */
	unsigned int  line;      /* line.. */

	void   *blk;
	size_t size;

	struct        __media_sysmem_info *next;
	struct        __media_sysmem_info *prev;
}media_sysmem_info;

/* 
 * G L O B A L   V A R I A B L E S
 *
 */
static media_sysmem_info *media_sysmem_list;
static media_sysmem_info *media_sysmem_last;
static unsigned int media_sysmem_node_count;
static unsigned int media_sysmem_total_mem;
static unsigned int media_sysmem_max_mem;
static pthread_mutex_t media_mem_lock;
static pthread_cond_t  media_mem_sig;
static int verbose=_ENABLE_VERVOSE;

static unsigned int log_cnt = 0;
static unsigned int tot_alloc_cnt = 0;
static unsigned int tot_alloc_len = 0;
static unsigned int tot_free_cnt  = 0;
static unsigned int tot_free_len  = 0;

/* 
 * F U N C T I O N S 
 *
 */
static char* _get_ftime(const char *format)
{
	static char timeStrBuf[32] = {0,};
	struct timeval tv;
	struct tm tt;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tt);

	memset(timeStrBuf, 0x00, 32);
	strftime(timeStrBuf, 32, format, &tt);

	return timeStrBuf;
}

static size_t _save_log_2_file(const char *fileName, void *buffer, size_t dataLen, int appndYN)
{
	int fd;
	size_t wrLen;

//	m_dbg("%s", (char *)buffer);

	if(appndYN) fd = open(fileName, O_WRONLY | O_CREAT | O_APPEND, 0644);
	else        fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if( 0 > fd )
    {
		m_dbg("Failed to open() - %d:%s\n", errno, strerror(errno));
		goto err;
	}
	
	wrLen = write(fd, buffer, dataLen);
	if( 0 > wrLen )
	{
		m_dbg("Failed to write() - %d:%s\n", errno, strerror(errno));
		goto err;
	}
	
	if(-1 == fsync(fd)) 
	{
		if(errno == EINVAL) 
		{
			if(-1 == fdatasync(fd)) 
			{
				m_dbg("Failed to fdatasync() - %d:%s\n", errno, strerror(errno));
				goto err;
			}
		}
		else
		{
			m_dbg("Failed to fsync() - %d:%s\n", errno, strerror(errno));
			goto err;
		}
	}

	close(fd);

	return wrLen;

err:
	m_dbg("Failed to save a \"%s\".\n", fileName);
	close(fd);

	return -1;
}

#define MEMINFO_LOG_DIR "/var/log"
static void _dump_log(const char *logMsg)
{
	char file_name[FILENAME_MAX] = {0,};
	size_t logLen = strlen(logMsg);

	// Doesn't exist log directory
	if(access(MEMINFO_LOG_DIR, F_OK))
	{
		m_dbg("There is no \"%s\"\n", MEMINFO_LOG_DIR);
		exit(EXIT_FAILURE);
	}

	// write log
	sprintf(file_name, "%s/%s_meminfo_%03d.txt", MEMINFO_LOG_DIR, _get_ftime("%Y_%m_%d"), log_cnt);
	_save_log_2_file(file_name, logMsg, logLen, 1);
}

static int _get_node_count(media_sysmem_info *head)
{
	int count = 0;
	media_sysmem_info *curnode = head;

	while(NULL != curnode)
	{
		curnode = curnode->next;
		count ++;
	}

	return count;
}

static media_sysmem_info *_get_curnode(media_sysmem_info *head, int idx)
{
	media_sysmem_info *curnode = head;

	while( (NULL != curnode) && (--idx >= 0) )
	{
		curnode = curnode->next;
	}

	return curnode;
}

static void _add_node(media_sysmem_info **head, media_sysmem_info *newnode)
{
	media_sysmem_info *tail = NULL;

	if(NULL == (*head))
	{
		*head = newnode;
	}
	else
	{
		tail = (*head);
		while(NULL != tail->next)
		{
			tail = tail->next;
		}

		tail->next = newnode;
		newnode->prev = tail;
	}
}

static void _destroy_node(media_sysmem_info *node)
{
	if(node->blk) 
		free(node->blk);

	if(node)
		free(node);
}

static void _remove_node(media_sysmem_info **head, media_sysmem_info *delnode)
{
	if(*head == delnode)
	{
		*head = delnode->next;
		if(*head)
			(*head)->prev = NULL;

		delnode->next = NULL;
		delnode->prev = NULL;
	}
	else
	{
		if(delnode->prev)
			delnode->prev->next = delnode->next;
		if(delnode->next)
			delnode->next->prev = delnode->prev;

		delnode->next = NULL;
		delnode->prev = NULL;
	}
}

/* initializing */
void media_mem_init(char *tag, int KbytesSize)
{
	int ix;
	char logbuff[1024] = {0,};
	
	//m_dbg("(%d)\n",KbytesSize);

	media_sysmem_list = NULL;
	media_sysmem_last = NULL;
	media_sysmem_node_count = 0;
	media_sysmem_total_mem  = 0;
	media_sysmem_max_mem    = (KbytesSize * 1024);
	pthread_mutex_init(&media_mem_lock,NULL);
	pthread_cond_init(&media_mem_sig,NULL);

	tot_alloc_cnt = 0;
	tot_alloc_len = 0;
	tot_free_cnt  = 0;
	tot_free_len  = 0;

	sprintf(logbuff, "+ %s: %s [start] memory info ====\n", tag, _get_ftime("%Y_%m_%d.%H:%M:%S"));
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
}

/* deleting... */
void media_mem_delete(char *tag)
{
	int i;
	int idx;
	unsigned int size;
	char logbuff[2048] = {0,};
	media_sysmem_info *trace = NULL;

	idx = _get_node_count(media_sysmem_list);
	size = 0;
	for(i = 0; i < idx; i++)
	{
		trace = _get_curnode(media_sysmem_list, 0);
		if(NULL != trace)
		{
			sprintf(logbuff, "\t%8d) loc=0x%08x, size=%4d  allocated by (%s:%d  %s)\n",
					i+1, (void*)trace->blk, trace->size, trace->func, trace->line, trace->file);
			_dump_log(logbuff);
			if(verbose) fprintf(stderr, logbuff);
			
			size += trace->size;

			_remove_node(&media_sysmem_list, trace);
			_destroy_node(trace);
		}
	}

	sprintf(logbuff, "\t-------------------------------------------------------------------------------\n");
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	sprintf(logbuff, "\tTotal alloc count: %8d times. Total alloc size: %8d bytes.\n", tot_alloc_cnt, tot_alloc_len);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
	
	sprintf(logbuff, "\tTotal free count : %8d times. Total free size : %8d bytes.\n", tot_free_cnt, tot_free_len);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
	
	sprintf(logbuff, "\tUnfreed count    : %8d times. Unfreed size    : %8d bytes.\n", idx, size);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	sprintf(logbuff, "\t-------------------------------------------------------------------------------\n");
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	media_sysmem_list = NULL;
	media_sysmem_last = NULL;
	media_sysmem_node_count = 0;
	media_sysmem_total_mem  = 0;
	media_sysmem_max_mem    = 0;

	tot_alloc_cnt = 0;
	tot_alloc_len = 0;
	tot_free_cnt  = 0;
	tot_free_len  = 0;

	sprintf(logbuff, "+ %s: %s [e n d] memory info ====\n", tag, _get_ftime("%Y_%m_%d.%H:%M:%S"));
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
	log_cnt ++;
}

/* verbose statistics */
unsigned int media_mem_stats(size_t *count)
{
	int i;
	unsigned int cnt;
	unsigned int size;
	media_sysmem_info *trace;
	char logbuff[2048] = {0,};

	//m_dbg("media_mem_stats\n");

	if(count){
		*count = media_sysmem_node_count;

		m_dbg("memory info ====\n");

		cnt = _get_node_count(media_sysmem_list);
		size = 0;
		for(i = 0; i < cnt; i++)
		{
			trace = _get_curnode(media_sysmem_list, i);
			if(NULL != trace)
			{
				size += trace->size;
				fprintf(stderr, "\t%8d) loc=0x%08x, size=%4d  allocated by (%s:%d  %s)\n",
						i+1, (void*)trace->blk, trace->size, trace->func, trace->line, trace->file);
			}
		}
	}

	sprintf(logbuff, "\t-------------------------------------------------------------------------------\n");
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	sprintf(logbuff, "\tTotal alloc count  : %8d times. Total alloc size : %8d bytes.\n", tot_alloc_cnt, tot_alloc_len);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
	
	sprintf(logbuff, "\tTotal free count   : %8d times. Total free size  : %8d bytes.\n", tot_free_cnt, tot_free_len);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);
	
	sprintf(logbuff, "\tCurrent Alloc Count: %8d times. Current Used size: %8d bytes.\n", cnt, size);
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	sprintf(logbuff, "\t-------------------------------------------------------------------------------\n");
	_dump_log(logbuff);
	m_dbg("%s", logbuff);

	return media_sysmem_total_mem;
}

/*
 * internal malloc function 
 */
static void *__media_memory_alloc(const char *file ,const int line, const char *func, size_t sz)
{
	int cnt = 0;
//	int tot_sz;
	char *blk;
	char *p;
	media_sysmem_info *newnode;

	//m_dbg("__alloc(size : %d)\n", sz);

//	tot_sz = sizeof(media_sysmem_info) + sz;

	while((media_sysmem_total_mem + sz) >= media_sysmem_max_mem)
	{
		m_dbg("memory full!! = %d kbytes\n",media_mem_stats(NULL)/1024);
		media_mem_stats(&cnt);
		pthread_mutex_unlock(&media_mem_lock);
		pthread_cond_wait(&media_mem_sig,&media_mem_lock);
	}

	newnode = (media_sysmem_info*)malloc(sizeof(media_sysmem_info));
	memset(newnode, 0x00, sizeof(media_sysmem_info));
	{
		snprintf(newnode->file, FILE_NAME_MAX, "%s", file);
		newnode->line = line;                          
		snprintf(newnode->func, FUNC_NAME_MAX, "%s", func);
		newnode->size = sz;
		newnode->next = NULL;
		newnode->prev = NULL;

	/*Alloc & Add here*/	
		newnode->blk = malloc(sz);
		_add_node(&media_sysmem_list, newnode);
		++tot_alloc_cnt;
		tot_alloc_len += sz;
	}

	++media_sysmem_node_count;
	media_sysmem_total_mem += sz;

	if(verbose) 
		m_dbg("\t[+] __alloc(0x%08x, %4d) size=%4d by (%s:%05d  %s)\n", 
				(void*)(newnode->blk), 
				media_sysmem_node_count, 
				newnode->size, 
				newnode->func, 
				newnode->line,
				newnode->file); 

	return newnode->blk;
}

/*
 * internal free function 
 */
static void __media_memory_free(const char *file ,const int line, const char *func, unsigned char *blk)
{
	media_sysmem_info *delnode;

	//m_dbg("__free\n");

	if(!blk){
		return ;
	}

	/* null list */ 
	if(media_sysmem_node_count==0){
		m_dbg("\t__free(0x%08x) - null list\n",(void*)blk);
		return ;
	}

	delnode = media_sysmem_list;
	while(delnode){
		if(delnode->blk == blk){
			--media_sysmem_node_count;
			media_sysmem_total_mem -= delnode->size;

			/* signalling */
			if( (media_sysmem_total_mem) <= (media_sysmem_max_mem/2) )
				pthread_cond_signal(&media_mem_sig);

			if(verbose) 
				m_dbg("\t[-] __free(0x%08x, %4d) size=%4d by (%s:%05d  %s)\n", 
						(void*)(delnode->blk), 
						media_sysmem_node_count,
						delnode->size, 
						delnode->func, 
						delnode->line,
						delnode->file); 
		/*Free & Remove here*/	
			_remove_node(&media_sysmem_list, delnode);
			_destroy_node(delnode);
			++tot_free_cnt;
			tot_free_len += delnode->size;

			return;
		}/*if(delnode->blk == blk) */
		delnode = delnode->next;
	}/*while(delnode)*/

	m_dbg("\t__free(0x%08x) -\e[31m Unlisted block  by (%s:%05d  %s) \e[0m\n", (void*)blk, func, line, file);
	free(blk);
	blk = NULL;
}

static int __media_memory_size(unsigned char *blk)
{
	int ix = 0;
	media_sysmem_info *trace;

	//m_dbg("__size()\n");

	trace = media_sysmem_list;
	while(trace){
		if(trace->blk == blk){
			return trace->size;
		}
		trace = trace->next;
	}

	m_dbg("\t__size(0x%08x) - cannot find !!\n",(void*)blk);

	return 0;
}

/*
 * P U B L I C    A P I s
 *
 */
void _media_free(const char *file, const int line, const char *func, void *blk)
{
	//m_dbg("free\n");

	pthread_mutex_lock(&media_mem_lock);
	if(verbose) 
		m_dbg("free=0x%08x <%s|%05d|%s> \n", (void*)blk, file, line, func);

	__media_memory_free(file, line, func, (char *)blk);
	pthread_mutex_unlock(&media_mem_lock);
}

void *_media_malloc(const char *file, const int line, const char *func, size_t sz)
{
	void *blk;

	//m_dbg("malloc(size : %d)\n",sz);

	pthread_mutex_lock(&media_mem_lock);

	blk = __media_memory_alloc(file, line, func, sz);
	if(verbose) 
		m_dbg("malloc(%4d)=0x%08x <%s|%05d|%s> \n", sz, (void*)blk, file, line, func);

	pthread_mutex_unlock(&media_mem_lock);
	return blk;
}

void *_media_calloc(const char *file, const int line, const char *func, size_t nmb, size_t sz)
{
	void *blk;

	//m_dbg("calloc(size : %d)\n", sz);

	pthread_mutex_lock(&media_mem_lock);
	
	blk = __media_memory_alloc(file, line, func, (nmb*sz));
	if(verbose) 
		m_dbg("calloc(%4d,%4d)=0x%08x <%s|%05d|%s> \n", nb, sz, (void*)blk, file, line, func);

	pthread_mutex_unlock(&media_mem_lock);
	return blk;
}

void *_media_realloc(const char *file, const int line, const char *func, void *ptr, int sz)
{  
	int olen;
	void *newblk;

	//m_dbg("realloc(size : %d)\n", sz);

	pthread_mutex_lock(&media_mem_lock);

	/* ----- */
	if(!ptr){
		if(sz>0){
			newblk = __media_memory_alloc(file, line, func, sz);
			if(verbose) 
				m_dbg("realloc(0x%08x,%4d)=0x%08x <%s|%05d|%s> \n",
						(void*)ptr, sz, (void*)newblk, file, line, func);
			pthread_mutex_unlock(&media_mem_lock);
			return newblk;
		}
		if(verbose) 
			m_dbg("realloc(0x%08x,%4d)=NULL <%s|%05d|%s> \n", (void*)ptr, sz, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	/* ---- */
	if(0 >= sz){
		__media_memory_free(file, line, func, ptr);
		if(verbose) 
			m_dbg("realloc(0x%08x,%4d)=NULL <%s|%05d|%s> \n", (void*)ptr, sz, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	olen = __media_memory_size(ptr);
	if(olen >= sz){ /* An original is longer than 'sz' */
		if(verbose) 
			m_dbg("realloc(0x%08x,%4d)=0x%08x - (%d,%d) <%s|%05d|%s> \n",
					(void*)ptr, sz, (void*)ptr, sz, olen, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return ptr;
	}

	newblk = __media_memory_alloc(file, line, func, sz);
	if(!newblk){
		m_dbg("realloc(0x%08x,%4d) -> no memory <%s|%05d|%s> \n", (void*)ptr, sz, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	memset(newblk,0,sz);
	memcpy(newblk,ptr,olen);

	__media_memory_free(file, line, func, ptr);

	if(verbose) 
		m_dbg("realloc(0x%08x,%4d)=0x%08x <%s|%05d|%s> \n", (void*)ptr, sz, (void*)newblk, file, line, func);

	ptr = NULL;

	pthread_mutex_unlock(&media_mem_lock);

	return newblk;
}

char *_media_strdup(const char *file, const int line, const char *func, const char *ptr)
{  
	int olen;
	char *newblk;

	//m_dbg("_media_strdup\n");

	pthread_mutex_lock(&media_mem_lock);

	/* ----- */
	if(!ptr){
		m_dbg("strdup(0x%08x) -> no memory <%s|%05d|%s> \n", (void*)ptr, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	/* ---- */
	olen = strlen(ptr);
	if(olen<=0){
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	newblk = (char *)__media_memory_alloc(file, line, func, olen+1);
	if(!newblk){
		m_dbg("strdup(0x%08x) -> no memory <%s|%05d|%s> \n", (void*)ptr, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	memset(newblk, 0, olen+1);
	memcpy(newblk, ptr, olen);

	if(verbose) 
		m_dbg("strdup(0x%08x=%s)=(0x%08x=%s) <%s|%05d|%s> \n", (void*)ptr, ptr, (void*)newblk, newblk, file, line, func);

	pthread_mutex_unlock(&media_mem_lock);

	return newblk;
}

char *_media_strndup(const char *file, const int line, const char *func, const char *ptr, size_t sz)
{  
	int olen;
	char *newblk;

	//m_dbg("_media_strdup\n");

	pthread_mutex_lock(&media_mem_lock);

	/* ----- */
	if(!ptr){
		m_dbg("strndup(0x%08x, %4d) -> no memory <%s|%05d|%s> \n", (void*)ptr, sz, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	/* ---- */
	if( 0 == sz )
		return NULL;

	olen = strlen(ptr);
	if(olen<=0){
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	if(sz < olen)
		olen = sz;

	newblk = (char *)__media_memory_alloc(file, line, func, sz+1);
	if(!newblk){
		m_dbg("strndup(0x%08x, %4d) -> no memory <%s|%05d|%s> \n", (void*)ptr, sz, file, line, func);
		pthread_mutex_unlock(&media_mem_lock);
		return NULL;
	}

	memset(newblk,0,sz+1);
	memcpy(newblk,ptr,sz);

	if(verbose) 
		m_dbg("strndup(0x%08x=%s)=(0x%08x=%s), sz:%d <%s|%05d|%s> \n", (void*)ptr, ptr, (void*)newblk, newblk, sz, file, line, func);

	pthread_mutex_unlock(&media_mem_lock);

	return newblk;
}
