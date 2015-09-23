/* Header file extracted from btr.c -- an ANSI C implementation
   included in the source code distribution of 

   SORTING AND SEARCHING ALGORITHMS: A COOKBOOK

   by THOMAS NIEMANN Portland, Oregon 
   email: thomasn@jps.net 
   home: http://members.xoom.com/thomasn/s_man.htm

   From the cookbook:

   Permission to reproduce this document, in whole or in part, is
   given provided the original web site listed below is referenced,
   and no additional restrictions apply. Source code, when part of a
   software project, may be used freely without reference to the
   author.

   Includes modifications by Marc-Andre Lemburg, 1998, mal@lemburg.com:
   * removed nearly all globals, namely the global pointer h
   * renamed many symbols
   * added cursor support
   * added bFlush() and bUpdateKey()
   * enhanced bFind*() functions to allow scanning the index without copying
     any data
   * removed some unnecessary stuff like hList
   * added EXTRA_BUFFERS
   * added bCursorReadData()
   * fixed a bug that caused a newly initialized root buffer not to
     written to disk (the modified flag was not set)
   * added external access to bErrLineNo in btr.h
   * fixed a bug in search(): when dealing with duplicates not the first
     but the second key was returned (at least sometimes)
   * added filemode support to bOpen()
   * added a fflush() to flushAll() to make sure the data is really
     written to disk and not just to the cache

*/

/*
 * this file is divided into sections:
 *   stuff you'll probably want to place in a .h file...
 *     implementation dependent
 *       - you'll probably have to change something here
 *     implementation independent
 *       - types and function prototypes that typically go in a .h file
 *     function prototypes
 *       - prototypes for user functions
 */

/****************************
 * implementation dependent *
 ****************************/

/* Maximal allowed sectorSize value */
#define MAX_SECTOR_SIZE	1024

typedef unsigned long bRecAddr; /* record address for external record */
typedef unsigned long bIdxAddr; /* record address for btree node */

#define CC_EQ           0
#define CC_GT           1
#define CC_LT          -1

/* compare two keys and return:
 *    CC_LT     key1 < key2
 *    CC_GT     key1 > key2
 *    CC_EQ     key1 = key2
 */
typedef int (*bCompFunc)(const void *key1, const void *key2);

/* Number of buffers to allocate in addition to the implementations
   minimum. This will enhance performance if you often read small
   sequences from the index or use many cursors. */
#define EXTRA_BUFFERS 10

/******************************
 * implementation independent *
 ******************************/

typedef enum {false, true} bool;
typedef enum {
    bErrOk,
    bErrKeyNotFound,
    bErrDupKeys,
    bErrSectorSize,
    bErrFileNotOpen,
    bErrFileExists,
    bErrNotWithDupKeys,
    bErrBufferInvalid,
    bErrIO,
    bErrMemory 
} bError;

typedef struct {                /* info for bOpen() */
    char *iName;                /* name of index file */
    int filemode;		/* Mode in which to open the file:

				   0 - try to open it in update mode,
				       revert to creating a new file
				       if that fails
				   1 - open the file in read-only mode,
				   2 - force creation of a new file

				 */
    int keySize;                /* length, in bytes, of key */
    bool dupKeys;               /* true if duplicate keys allowed */
    int sectorSize;             /* size of sector on disk */
    bCompFunc comp;             /* pointer to compare function */
} bDescription;

typedef char bKey;           	/* keys entries are treated as char arrays */

typedef struct {
    unsigned int leaf:1;        /* first bit = 1 if leaf */
    unsigned int ct:15;         /* count of keys present */
    bIdxAddr prev;              /* prev node in sequence (leaf) */
    bIdxAddr next;              /* next node in sequence (leaf) */
    bIdxAddr childLT;           /* child LT first key */
    /* ct occurrences of [key,rec,childGE] */
    bKey fkey;               	/* first occurrence */
} bNode;

typedef struct bBufferTag {     /* location of node */
    struct bBufferTag *next;    /* next */
    struct bBufferTag *prev;    /* previous */
    bIdxAddr adr;               /* on disk */
    bNode *p;                	/* in memory */
    bool valid;                 /* true if buffer contents valid */
    bool modified;              /* true if buffer modified */
} bBuffer;

typedef struct bHandle {
    FILE *fp;                   /* idx file */
    int keySize;                /* key length */
    bool dupKeys;               /* true if duplicate keys */
    int sectorSize;             /* block size for idx records */
    bCompFunc comp;             /* pointer to compare routine */
    bBuffer root;               /* root of b-tree, room for 3 sets */
    bBuffer bufList;            /* head of buf list */
    void *malloc1;              /* malloc'd resources */
    void *malloc2;              /* malloc'd resources */
    bBuffer gbuf;               /* gather buffer, room for 3 sets */
    unsigned int maxCt;         /* minimum # keys in node */
    int ks;                     /* sizeof key entry */
    bIdxAddr nextFreeAdr;       /* next free b-tree record address */

    /* statistics */
    int maxHeight;          	/* maximum height attained */
    int nNodesIns;          	/* number of nodes inserted */
    int nNodesDel;          	/* number of nodes deleted */
    int nKeysIns;           	/* number of keys inserted */
    int nKeysDel;           	/* number of keys deleted */
    int nKeysUpd;           	/* number of key updates */
    int nDiskReads;         	/* number of disk reads */
    int nDiskWrites;        	/* number of disk writes */

} bHandle;

/* Note: Cursors are only valid if their buffer is. */

typedef struct bCursor {
    bBuffer *buffer;            /* buffer in which the key is stored */
    bKey *key;            	/* pointer to key (in buffer) */
} bCursor;


/* Line number for last IO or memory error */
extern int bErrLineNo;

/***********************
 * function prototypes *
 ***********************/

bError bOpen(bDescription info, bHandle **handle);
    /*
     * input:
     *   info                   info for open
     * output:
     *   handle                 handle to btree, used in subsequent calls
     * returns:
     *   bErrOk                 open was successful
     *   bErrMemory             insufficient memory
     *   bErrSectorSize         sector size too small or not 0 mod 4
     *   bErrFileNotOpen        unable to open index file
     */

bError bFlush(bHandle *handle);
    /*
     * input:
     *   handle                 handle returned by bOpen
     * returns:
     *   bErrOk                 file closed, resources deleted
     * notes:
     *   Flushes all buffers to disk
     */

bError bClose(bHandle *handle);
    /*
     * input:
     *   handle                 handle returned by bOpen
     * returns:
     *   bErrOk                 file closed, resources deleted
     */

bError bInsertKey(bHandle *handle, void *key, bRecAddr rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   key                    key to insert
     *   rec                    record address
     * returns:
     *   bErrOk                 operation successful
     *   bErrDupKeys            duplicate keys (and info.dupKeys = false)
     * notes:
     *   If dupKeys is false, then all records inserted must have a
     *   unique key.  If dupkeys is true, then duplicate keys are
     *   allowed, but they must all have unique record addresses.
     *   In this case, record addresses are included in internal
     *   nodes to generate a "unique" key.
     */

bError bUpdateKey(bHandle *handle, void *key, bRecAddr rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   key                    key to update
     *   rec                    new record address
     * returns:
     *   bErrOk                 operation successful
     *   bErrNotFound           key not found
     *   bErrNotAllowed         operation not allowed
     * notes:
     *   This operation is only possible if dupKeys is false due to
     *   the way duplicate keys are handled by the implementation.
     */

bError bDeleteKey(bHandle *handle, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   key                    key to delete
     *   rec                    record address of key to delete
     * output:
     *   rec                    record address deleted
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     * notes:
     *   If dupKeys is false, all keys are unique, and rec is not used
     *   to determine which key to delete.  If dupKeys is true, then
     *   rec is used to determine which key to delete.
     */

bError bFindKey(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   key                    key to find
     * output:
     *   cursor			cursor pointing to new position
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     */

bError bFindFirstKey(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     * output:
     *   cursor			cursor pointing to new position
     *   key                    first key in sequential set (if != NULL)
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     */

bError bFindLastKey(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     * output:
     *   cursor			cursor pointing to new position
     *   key                    last key in sequential set (if != NULL)
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     */

bError bFindNextKey(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   cursor			cursor pointing to current position
     * output:
     *   cursor			cursor pointing to new position
     *   key                    key found (if != NULL)
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     */

bError bFindPrevKey(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   cursor			cursor pointing to current position
     * output:
     *   cursor			cursor pointing to new position
     *   key                    key found (if != NULL)
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrKeyNotFound        key not found
     */

bError bCursorReadData(bHandle *handle, bCursor *c, void *key, bRecAddr *rec);
    /*
     * input:
     *   handle                 handle returned by bOpen
     *   cursor			cursor pointing to current position
     * output:
     *   key                    key found (if != NULL)
     *   rec                    record address (if != NULL)
     * returns:
     *   bErrOk                 operation successful
     *   bErrBufferInvalid      cursor buffer is invalid
     */

/* Debugging function which validates an open BTree pointed to by
   handle and returns 0 for a valid tree structure and a negative
   result for an invalid structure. */

int bValidateTree(bHandle *handle);
