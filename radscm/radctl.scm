;;;; This file is part of GNU RADIUS.
;;;; Copyright (C) 2001, Sergey Poznyakoff
;;;;
;;;; This program is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2 of the License, or
;;;; (at your option) any later version.
;;;;
;;;; This program is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.
;;;;
;;;; You should have received a copy of the GNU General Public License
;;;; along with this program; if not, write to the Free Software
;;;; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;;;;
;;;; $Id$

(use-modules (ice-9 getopt-long))

(define opt-login #f)
(define opt-passwd #f)
(define flag-verbose #f)
(define radctl-prompt "radctl> ")

(define (string-ws str)
  (let ((len (string-length str)))
    (let ((i (do ((index (1- len) (1- index)))
		 ((or (< index 0)
		      (char-whitespace? (string-ref str index)))
		  index))))
      (cond
       ((< i 0)
	#f)
       (else
	i)))))

(define (string-tokenize str)
  (let loop ((fields '())
	     (str str))
       (cond
	((string-ws str)
	 => (lambda (w)
	      (if w
		  (loop
		   (let ((s (substring str (+ 1 w))))
		     (cond
		      ((= (string-length s) 0)
		       fields)
		      (else
		       (cons s fields))))
		   (substring str 0 w))
		  fields)))
	((= (string-length str) 0)
	 fields)
	(else (append (list str) fields)))))

(define (message text list)
  (format #t "~A" text)
  (if (not (null? list))
      (begin
	(format #t ": ")
	(for-each (lambda (x)
		    (format #t "~A\n" x))
		  list)))
  (format #t "\n"))

(define (ok . rest)
  (message "Ok" rest))

(define (error . rest)
  (message "ERROR" rest))

(define (rad-cntl command cmdlist)
  (let* ((state (symbol->string command))
	 (pack (list (cons "User-Name"  opt-login)
		     (cons "Password"  opt-passwd)
		     (cons "State" state))))
    (let ((ans (rad-send :port-cntl :auth-req
			 (if (null? cmdlist)
			     pack
			     (append pack (list (cons "Class" (car cmdlist)))))
			 flag-verbose)))
      (cond
       ((null? ans)
	(format #t "FAILED\n"))
       (else
	(if (= (car ans) :auth-ack)
	    (format #t "OK\n")
	    (format #t "ERROR\n"))
	(rad-format-reply-msg (cdr ans))
	(format #t "\n"))))))


(define (my-read-line)
  (if (isatty? (current-input-port))
      (format #t "~A" radctl-prompt))
  (read-line))

(define (help)
  (format #t "These commands are understood by radctl:\n") 
  (format #t "   bye,quit              Quit the program\n")
  (format #t "   help                  Display this help\n")
  (format #t "   login,user STRING     Change username\n")
  (format #t "   password [STRING]     Change password\n")
  (format #t "   verbose               Flip verbose state\n")
  (format #t "   server                Display current server ID\n")
  (format #t "   server NAME           Select another server\n")
  (format #t "   list                  Display all configured servers\n")
  (format #t "\nThese commands are sent directly to the server:\n")
  (format #t "   getpid                Return the PID of the master Radius process\n")
  (format #t "   get-m-stat            Get memory utilization statistics\n")
  (format #t "   get-q-stat            Get request queue statistics\n")
  (format #t "   dumpdb                Dump current database\n")
  (format #t "   reload [WHAT]         Reload configuration\n")
  (format #t "                         WHAT shows which item to reload\n")
  (format #t "Be careful with these:\n")
  (format #t "   restart               Restart the server\n")
  (format #t "   shutdown              Shut the server down\n")
  (format #t "   suspend               Suspend the server\n")
  (format #t "   continue              Undo the last suspend command\n")
  (format #t "\nAny unambiguous abbreviation of the above commands is also accepted.\n"))

(define completions
  '((bye 1)
    (quit 1)
    (help 1)
    (login 2)
    (user 1)
    (password 1)
    (verbose 1)
    (server 2)
    (list 2)
    ;;
    (getpid 3)
    (get-m-stat 5)
    (get-q-stat 4)
    (reload 3)
    (restart 3)
    (dumpdb 1)
    (shutdown 2)
    (suspend 2)
    (continue 1)))
    
(define (complete-command str)
  (let ((len (string-length str)))
    (do ((comp completions (cdr comp))
	 (match #f))
	((or (null? comp) match) match)
      ;; Here (caar comp) contains the pretender's symbol
      ;; and (cadar comp) contains minimal match length
      (let ((p-string (symbol->string (caar comp)))
	    (p-len (cadar comp)))
	(if (and (>= len (cadar comp)) (<= len (string-length p-string)) 
		 (string=? str (substring (caar comp) 0 len)))
	    (set! match (caar comp)))))))

(define (read-commands)
  (do ((line (my-read-line) (my-read-line)))
      (#f)
    (let ((cmd (cond
		((eof-object? line)
		 (if (isatty? (current-input-port))
		     (ok "Bye"))
		 (exit 0))
		(else
		 (string-tokenize line)))))
;      (format #t "~A\n" (cddr cmd))
      (if (> (length cmd) 0)
	  (cond
	   ((complete-command (car cmd))
	    => (lambda (command-word)
		 (case (string->symbol command-word)
		   ((bye quit)
		    (exit))
		   ((help)
		    (help))
		   ((login user)
		    (cond
		     ((null? (cdr cmd))
		      (error "no user name\n"))
		     (else
		      (set! opt-login (cadr cmd))
		      (ok (if flag-verbose
			      "Don't forget to change password\n"
			      "")))))
		   ((password)
		    (set! opt-passwd (cond
				      ((null? (cdr cmd))
				       (rad-read-no-echo "Password: "))
				      (else
				       (cdr cmd)))))
		   ((list)
		    (cond
		     ((or (null? (cdr cmd))
			  (string=? (cadr cmd) "active"))
		      (for-each (lambda (x)
				  (format #t "~A ~A\n"
					  (car x) (cadr x)))
				(rad-client-list-servers)))
		     ((string=? (cadr cmd) "avail")
		      (rad-list-servers))
		     (else
		      (error "usage: list {active|avail}"))))
		   ((verbose)
		    (set! flag-verbose (not flag-verbose))
		    (format #t "radctl is now ~A\n"
			    (if flag-verbose "verbose" "silent")))
		   ((server)
		    (cond
		     ((null? (cdr cmd))
		      (format #t "Current server is ~A\n" (rad-get-server)))
		     (else
		      (if (rad-select-server (cadr cmd))
			  (ok)
			  (error "no such server")))))
		   (else
		    (cond
		     ((and opt-login opt-passwd)
		      (rad-cntl command-word (cdr cmd)))
		     (else
		      (error "no username/password")))))))
	   (else
	    (error "unknown or ambiguous command")))))))

;;; Command line options
(define grammar
  `((help (single-char #\h))   
    (login  (single-char #\l)
            (value #t))
    (user (single-char #\u)
	  (value #t))
    (password (value #t)
	    (single-char #\p))
    (server (value #t)
	    (single-char #\s))
    (verbose (single-char #\v))))

(define (usage)
    (format #t "usage: radctl.scm [options]\n")
    (format #t "\nOptions are:\n")
    (format #t "     -l, --login STRING\n")
    (format #t "     -p, --password STRING\n")
    (format #t "     -S, --server STRING\n")
    (format #t "     -v, --verbose\n"))

(define (cons? p)
  (and (pair? p) (not (list? p))))

;;; Main begins here

;; Read profile(s)
(load (string-append %raddb-path "/radctl.rc"))
(let ((localrc (string-append (passwd:dir (getpwuid (getuid))) ".radctl")))
  (if (file-exists? localrc)
      (load localrc)))

;; Parse command line
(for-each (lambda (x)
	    (and (cons? x)
		 (case (car x)
		   ((help)
		    (usage)
		    (exit 0))
		   ((login user)
		    (set! opt-login (cdr x)))
		   ((password)
		    (set! opt-passwd (if (string=? (cdr x) ".")
					 (rad-read-no-echo "Password: ")
					 (cdr x))))
		   ((verbose)
		    (set! flag-verbose (not flag-verbose)))
		   ((server)
		    (rad-select-server (cdr x))))))
	  (getopt-long (command-line) grammar))

;; main loop    
(read-commands)
