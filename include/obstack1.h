#define obstack_chunk_alloc emalloc
#define obstack_chunk_free efree
#ifdef HAVE_OBSTACK
# include <obstack.h>
#else
# include <../lib/obstack.h>
#endif
