#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#include <slist.h>

void
free_slist(s, f)
	struct slist *s;
	void (*f)();
{
	struct slist *next;

	while (s) {
		next = s->next;
		if (f)
			(*f)(s);
		free_entry(s);
		s = next;
	}
}

struct slist *
find_slist(s, f, v)
	struct slist *s;
	int (*f)();
	void *v;
{
	for (; s && (*f)(s, v); s = s->next) 
		;
	return s;
}

struct slist *
append_slist(s, e)
	struct slist *s, *e;
{
	struct slist *p;

	if (!s)
		return e;
	for (p = s; p->next; p = p->next)
		;
	p->next = e;
	return s;
}

struct slist *
reverse_slist_internal(s, p)
	struct slist *s, *p;
{
	struct slist *t;
	
	if (!p)
		return s;
	t = p;
	p = p->next;
	t->next = s;
	return reverse_slist_internal(t, p);
}

struct slist *
reverse_slist(s)
	struct slist *s;
{
	return reverse_slist_internal((struct slist *)0, s);
}
