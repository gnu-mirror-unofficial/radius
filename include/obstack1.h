#define obstack_chunk_alloc grad_emalloc
#define obstack_chunk_free grad_free
#ifdef HAVE_OBSTACK
# include <obstack.h>
#else
# include <../lib/obstack.h>
#endif
