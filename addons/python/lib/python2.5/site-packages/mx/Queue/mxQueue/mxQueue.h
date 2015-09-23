#ifndef MXQUEUE_H
#define MXQUEUE_H
/* 
  mxQueue -- A queue implementation

  Copyright (c) 1998-2000, Marc-Andre Lemburg; mailto:mal@lemburg.com
  Copyright (c) 2000-2007, eGenix.com Software GmbH; mailto:info@egenix.com
  See the documentation for further copyright information or contact
  the author (mailto:mal@lemburg.com).
  
*/

/* The extension's name; must be the same as the init function's suffix */
#define MXQUEUE_MODULE "mxQueue"

/* Name of the package or module that provides the extensions C API.
   If the extension is used inside a package, provide the complete
   import path. */
#define MXQUEUE_API_MODULE "mx.Queue"

/* --- No servicable parts below this line ----------------------*/

/* Include generic mx extension header file */
#include "mxh.h"

/* Include Python compatibility header file */
#include "mxpyapi.h"

#ifdef MX_BUILDING_MXQUEUE
# define MXQUEUE_EXTERNALIZE MX_EXPORT
#else
# define MXQUEUE_EXTERNALIZE MX_IMPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* --- Queue Object ------------------------------------------*/

typedef struct {
    PyObject_HEAD
    Py_ssize_t size;			/* Number of items allocated */
    Py_ssize_t head;			/* Index of head element */
    Py_ssize_t tail;			/* Index of tail element */
    PyObject **array;			/* Pointer to the queue array */
} mxQueueObject;

/* Fast access */

#define mxQueue_GET_SIZE(v) \
        ((((mxQueueObject *)(v))->head - ((mxQueueObject *)(v))->tail) \
	 % ((mxQueueObject *)(v))->size)
#define mxQueue_EMPTY(v) \
        (((((mxQueueObject *)(v))->head - ((mxQueueObject *)(v))->tail)) == 0)

/* Type checking macro */

#define mxQueue_Check(v) \
        (((mxQueueObject *)(v))->ob_type == mxQueue.Queue_Type)

/* --- C API ----------------------------------------------------*/

/* C API for usage by other Python modules */
typedef struct {
	 
    /* Type object for Queue() */
    PyTypeObject *Queue_Type;

    /* Create a new empty queue object with at least size entries
       alredy allocated. */
    mxQueueObject *(*mxQueue_New)(Py_ssize_t size);

    /* Push a Python object onto the queue. The reference count is increased
       by one. Queues only grow, they never shrink again. */
    int (*mxQueue_Push)(mxQueueObject *queue,
			PyObject *v);
    
    /* Pop an object from the queue. Ownership is passed to the caller.
       Note: This doesn't cause the allocated queue size to change. */
    PyObject *(*mxQueue_Pop)(mxQueueObject *queue);
    
    /* Clear the queue. */
    int (*mxQueue_Clear)(mxQueueObject *queue);

    /* Get the number of entries in the queue. */
    Py_ssize_t (*mxQueue_Length)(mxQueueObject *queue);

    /* Create a new empty queue object from the sequence v */
    mxQueueObject *(*mxQueue_FromSequence)(PyObject *v);

    /* Return a the queues content as tuple. */
    PyObject *(*mxQueue_AsTuple)(mxQueueObject *queue);
    
    /* Return a the queues content as list. */
    PyObject *(*mxQueue_AsList)(mxQueueObject *queue);

    /* Pop the topmost n entries from the queue and return them as
       tuple. If there are not enough entries only the available ones
       are returned.  */
    PyObject *(*mxQueue_PopMany)(mxQueueObject *queue,
				Py_ssize_t n);

    /* Push the entries from sequence onto the queue. */
    int (*mxQueue_PushMany)(mxQueueObject *queue,
			    PyObject *sequence);

} mxQueueModule_APIObject;

#ifndef MX_BUILDING_MXQUEUE

/* Interfacestructure to C API for other modules.
   Call mxQueue_ImportModuleAPI() to initialize this
   structure. After that usage is simple:

   PyObject *v;
	
   v = mxQueue.Queue_New(0);
   if (!v)
       goto onError;
   ...

*/

static 
mxQueueModule_APIObject mxQueue;

/* You *must* call this before using any of the functions in
   mxQueue and check its outcome; otherwise all accesses will
   result in a segfault. Returns 0 on success. */

#ifndef DPRINTF
# define DPRINTF if (0) printf
#endif

static
int mxQueue_ImportModuleAndAPI(void)
{
    PyObject *mod, *v = 0;
    void *api;
    
    DPRINTF("Importing the %s C API...\n",MXQUEUE_API_MODULE);
    mod = PyImport_ImportModule(MXQUEUE_API_MODULE);
    if (mod == NULL)
	goto onError;
    DPRINTF(" module found\n");
    v = PyObject_GetAttrString(mod,MXQUEUE_MODULE"API");
    if (v == NULL)
	goto onError;
    Py_DECREF(mod);
    DPRINTF(" API object found\n");
    api = PyCObject_AsVoidPtr(v);
    if (api == NULL)
	goto onError;
    Py_DECREF(v);
    memcpy(&mxQueue,api,sizeof(mxQueue));
    DPRINTF(" API object initialized.\n");
    return 0;
    
 onError:
    DPRINTF(" not found.\n");
    Py_XDECREF(mod);
    Py_XDECREF(v);
    return -1;
}

#endif

/* EOF */
#ifdef __cplusplus
}
#endif
#endif
