/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_TERMCAP_H
# include <termcap.h>
#endif
#include <sys/ioctl.h>

#ifdef CBREAK
# include <sgtty.h>
# define SGTTY
#else
# ifdef TCGETA
#  define TERMIO
#  include <termio.h>
# else
#  define TERMIOS
#  include <termios.h>
# endif
#endif

#include <log.h>
#include <display.h>
#include <screen.h>

int             smart_terminal; /* Set to 1 if we're on a smart terminal */
int             overstrike;     /* Set to 1 if the terminal overstrikes */
/* Screen size: */
int             screen_length;
int             screen_width;

/*
 * Values from termcap database
 */
char            ch_erase;
char            ch_kill;
char           *clear_line;
char           *clear_screen;
char           *cursor_motion;
char           *terminal_init;
char           *terminal_end;
char           *start_standout;
char           *end_standout;

char            termcap_buf[1024];
char            string_buffer[1024];

#define lower_left tgoto(cursor_motion, 0, screen_length - 1)

/*
 * sysdep_init_screen() performs terminal initializations that depend
 * on sort of interface we are using.
 *
 * sysdep_restore_screen() does the same for restoring the terminal
 * settings.
 */
#ifdef SGTTY
struct sgttyb old_settings, new_settings;
int old_lword, new_lword;
# define save_settings() ioctl(STDOUT, TIOCGETP, &old_settings) 

int
sysdep_init_screen()
{
	if (ioctl(STDOUT, TIOCGETP, &old_settings) != -1) {
		/*
		 * cbreak on,
		 * echo off
		 * tab expansion off
		 */
		new_settings.sg_flags |= CBREAK;
		new_settings.sg_flags &= ~(ECHO | XTABS);
		ioctl(STDOUT, TIOCSETP, &new_settings);

		ch_erase = old_settings.sg_erase;
		ch_kill = old_settings.sg_kill;

#ifdef TOStop
		/* preserve and modify local mode word */
		ioctl(STDOUT, TIOCLGET, &old_lword);
		new_lword = old_lword | LTOSTOP;
		ioctl(STDOUT, TIOCLSET, &new_lword);
#endif
		return 0;
	}
	return 1;
}

int
sysdep_restore_screen()
{
	ioctl(STDOUT, TIOCSETP, &old_settings);
#ifdef TOStop
	ioctl(STDOUT, TIOCLSET, &old_lword);
#endif
}

#elif defined(TERMIO)
struct termio old_settings, new_settings;
# define save_settings() ioctl(STDOUT, TCGETA, &old_settings) 

int
sysdep_init_screen()
{
	if (ioctl(STDOUT, TCGETA, &old_settings) != -1) {
		new_settings.c_lflag &= ~(ICANON | ECHO);
		new_settings.c_oflag &= ~(TAB3);
		new_settings.c_cc[VMIN] = 1;
		new_settings.c_cc[VTIME] = 0;
		ioctl(STDOUT, TCSETA, &new_settings);

		ch_erase = old_settings.c_cc[VERASE];
		ch_kill = old_settings.c_cc[VKILL];

		return 0;
	}
	return 1;
}

int
sysdep_restore_screen()
{
	ioctl(STDOUT, TCSETA, &old_settings);
}

#elif defined(TERMIOS)
struct termios old_settings, new_settings;
# define save_settings() tcgetattr(STDOUT, &old_settings)

int
sysdep_init_screen()
{
	if (tcgetattr(STDOUT, &old_settings) != -1) {
		new_settings.c_lflag &= ~(ICANON | ECHO);
		new_settings.c_oflag &= ~(TAB3);
		new_settings.c_cc[VMIN] = 1;
		new_settings.c_cc[VTIME] = 0;
		tcsetattr(STDOUT, TCSADRAIN, &new_settings);

		ch_erase = old_settings.c_cc[VERASE];
		ch_kill = old_settings.c_cc[VKILL];

		return 0;
	}
	return 1;
}

int
sysdep_restore_screen()
{
	tcsetattr(STDOUT, TCSADRAIN, &old_settings);
}

#endif



void
init_termcap(inter)
	int inter;
{
	int  rc;
	char *termname;
	char *bufptr = string_buffer;
	
	/*
	 * Determine screen size
	 */
	screen_size();
	
	if (!inter) {
		smart_terminal = 0;
		return;
	}
	smart_terminal = 1;
	
	if ((termname = getenv("TERM")) == NULL) {
		/* No terminal; Try ansi */
		termname = "ansi";
	}

	if ((rc = tgetent(termcap_buf, termname)) != 1) {
		if (rc == -1) {
			radlog(L_ERR, _("can't open termcap file")) ;
		} else {
			radlog(L_ERR,
			       _("no termcap entry for a `%s' terminal"),
			    termname);
		}
		smart_terminal = 0;
		return ;
	}

	/* test "hardcopy" capability */
	if (tgetflag("hc") ||
	    (clear_screen = tgetstr("cl", &bufptr)) == NULL ||
	    (cursor_motion = tgetstr("cm", &bufptr)) == NULL) {
		smart_terminal = 0;
		return;
	}
	
	/*
	 * Determine actual screen size
	 */
	if ((screen_length = tgetnum("li")) <= 0) {
		screen_length = 0;
		smart_terminal = 0;
		return;
	}

	if ((screen_width = tgetnum("co")) == -1) {
		screen_width = 79;
	} else {
		screen_width -= 1;
	}
	
	/*
	 * Read the needed capabilities
	 */
	overstrike = tgetflag("os");
	/* ce = clear to end */
	if (!overstrike) {
		clear_line = tgetstr("ce", &bufptr);
	}

	if (save_settings() == -1)
		smart_terminal = 0;

	terminal_init = tgetstr("ti", &bufptr);
	terminal_end = tgetstr("te", &bufptr);
	start_standout = tgetstr("so", &bufptr);
	end_standout = tgetstr("se", &bufptr);	
}

/*
 * At invocation, old_setting should already be filled properly.
 */
void
init_screen()
{
	new_settings = old_settings;
	if (sysdep_init_screen())
		smart_terminal = 0;
	else
		putcap(terminal_init);
}

void
restore_screen()
{
	if (smart_terminal) {
		putcap(lower_left);
		putcap(clear_line);
		fflush(stdout);
		putcap(terminal_end);
	}
	sysdep_restore_screen();
}

void
screen_size()
{
#if defined(TIOCGWINSZ)
	struct winsize  sz;
# define CTLCODE TIOCGWINSZ
# define NLINES ws_row
# define NCOLS ws_col	
#elif defined(TIOCGSIZE)
	struct ttysize  sz;
# define CTLCODE TIOCGSIZE
# define NLINES	ts_lines
# define NCOLS	ts_cols
#endif
	
	/*
	 * Default screen size
	 */
	screen_width = MAX_COLS;
	screen_length = 0;

	if (ioctl(STDOUT, CTLCODE, &sz) != -1) {
		if (sz.NLINES != 0) {
			screen_length = sz.NLINES;
		}
		if (sz.NCOLS != 0) {
			screen_width = sz.NCOLS - 1;
		}
	}
}	
	

/*
 * A subroutine for tputs
 */
int
putstdout(c)
	char c;
{
	putc(c, stdout);
}

void
clear()
{
	if (smart_terminal) {
		putcap(clear_screen);
	}
}

int
clear_eol(len)
	int len;
{
	if (smart_terminal && !overstrike && len > 0) {
		if (clear_line) {
			putcap(clear_line);
			return 0;
		} else {
			fprintf(stdout, "%*.*s", len, len, "");
			return 1;
		}
	}
	return -1;
}

void
standout(msg)
	char  *msg;
{
	if (smart_terminal) 
		putcap(start_standout);
	fputs(msg, stdout);
	if (smart_terminal) 
		putcap(end_standout);
}
