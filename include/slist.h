struct slist {
	struct slist *next;
};

void free_slist(struct slist *s, void (*f)());
struct slist * find_slist(struct slist *s, int (*f)(), void *v);
struct slist * append_slist(struct slist *s, struct slist *e);
struct slist * reverse_slist(struct slist *s);
