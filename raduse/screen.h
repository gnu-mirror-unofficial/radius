#define	STDOUT	1

#define termputs(str)	tputs(str, STDOUT, (int (*)())putstdout)
#define putcap(str)	(void)((str) != NULL ? termputs(str) : 0)
#define Move_to(x, y)	termputs(tgoto(cursor_motion, x, y))

extern int smart_terminal;
extern int overstrike;
extern int screen_length;
extern int screen_width;

extern char ch_erase;
extern char ch_kill;

extern char *clear_line;
extern char *clear_screen;
extern char *cursor_motion;
extern char *terminal_init;
extern char *terminal_end;
extern char *start_standout;
extern char *end_standout;

void screen_size();
int putstdout(char c);

