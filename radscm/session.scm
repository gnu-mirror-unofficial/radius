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

(define opt-login "")
(define opt-passwd "")
(define opt-port 0)
(define opt-sid "00000000")
(define opt-nas "127.0.0.1")

(define action nil)
(define flag-verbose #f)

(define grammar
  `((login  (single-char #\l)
            (value #t))
    (passwd (value #t)
	    (single-char #\p))
    (nas (single-char #\n)
	 (value #t))
    (port (single-char #\P)
	  (value #t))
    (sid (single-char #\s)
	 (value #t))
    (verbose (single-char #\v))
    (start)
    (stop)
    (auth)
    (help (single-char #\h))))

(define (cons? p)
  (and (pair? p) (not (list? p))))

(define (check-vars act . rest)
  (let ((quit #f))
    (for-each (lambda (var)
		(cond
		 ((not (assoc var cmd-list))
		  (format #t "--~A not specified\n"
			  var)
		  (set! quit #t))))
	      rest)
    (if quit
	(begin
	  (format #t "Can't continue: --~A needs above options\n" act)
	  (exit 0)))))

;; cut here

(define (get-value name plist)
  (do ((tail plist (cdr tail)))
      ((or (null? tail) (string=? (car (car tail)) name))
       (cond
	((null? tail)
	 tail)
	(else
	 (cdr (car tail)))))))

(define (rad-auth)
  (let ((pack (list (cons "User-Name"  opt-login)
		    (cons "Password"  opt-passwd)
		    (cons "NAS-IP-Address" opt-nas))))
    (cond
     ((and (defined? 'opt-port) (number? opt-port))
      (set! pack (append pack (list (cons "NAS-Port-Id" opt-port))))))
    (rad-send :port-auth :auth-req pack flag-verbose)))

(define (rad-acct acct-type . plist)
  (let ((pack (list (cons "User-Name"  opt-login)
		    (cons "Acct-Status-Type" acct-type)
		    (cons "Acct-Session-Id" opt-sid))))
    (cond
     ((and (defined? 'opt-port) (number? opt-port))
      (set! pack (append pack (list (cons "NAS-Port-Id" opt-port))))))
    (rad-send :port-acct :acct-req
	      (cond
	       ((pair? plist)
		(append pack (car plist)))
	       (else
		pack))
	      flag-verbose)))

(define (check-auth)
  (check-vars 'auth 'login 'passwd)
  (let ((auth (rad-auth)))
    (cond
     ((null? auth)
      (format #t "Authentication failed\n"))
     ((= (car auth) :auth-ack)
      (format #t "Acknowledged\n"))
     ((= (car auth) :auth-rej)
      (format #t "REJECTED\n"))
     ((= (car auth) :access-challenge)
      (format #t "Acknowledged (challenge received)\n"))
     (else
      (format #t "Don't know. Code ~A\n" (rad-format-code #f (car auth)))))))

(define (session-start)
  (check-vars 'start 'login 'passwd 'sid)
  (let ((auth (rad-auth)))
    (let loop ((auth auth))
      (cond
       ((null? auth)
	(format #t "Authentication failed\n"))
       (else
	(cond
	 ((= (car auth) :auth-ack)
	  (let ((acct (rad-acct (rad-dict-name->value
				 "Acct-Status-Type" "Start")
				(cdr auth))))
	    (cond
	     ((null? acct)
	      (format #t "Accounting failed\n"))
	     (else
	      (cond 
	       ((= (car acct) :acct-resp)
		(format #t "Accounting OK\n"))
	       (else
		(format #t "Accounting failed: response ~A\n"
			(rad-format-code #f (car acct)))
		(rad-format-reply-msg (cdr auth) "Reply Message:")))))))
	 ((= (car auth) :auth-rej)
	  (format #t "Authentication failed\n")
	  (rad-format-reply-msg (cdr auth) "Reply Message:"))
	 ((= (car auth) :access-challenge)
	  (rad-format-reply-msg (cdr auth) "Reply Message:")
	  (let ((menu (get-value "State" (cdr auth)))
		(line (read-line (current-input-port))))
	    (loop
	     (rad-send :port-auth :auth-req (list
					     (cons "User-Name"  opt-login)
					     (cons "Password" line)
					     (cons "State" menu))
		       flag-verbose))))
	 (else
	  (format #t "Authentication failed: code ~A\n"		
		  (rad-format-code #f (car auth)))
	  (rad-format-reply-msg (cdr auth) "Reply Message:"))))))))

(define (session-stop)
  (check-vars 'stop 'login 'sid)
  (let ((acct (rad-acct (rad-dict-name->value "Acct-Status-Type" "Stop"))))
    (cond
     ((null? acct)
      (format #t "Accounting failed\n"))
     (else
      (cond 
       ((= (car acct) :acct-resp)
	(format #t "Accounting OK\n"))
       (else
	(format #t "Accounting failed: response ~A\n"
		(rad-format-code #f (car acct)))
	(rad-format-reply-msg (cdr auth) "Reply Message:")))))))

(define (usage)
  (format #t "usage: session.scm [options] {--auth|--start|--stop}\n")
  (format #t "\nOptions are:\n")
  (format #t "     -l, --login STRING\n")
  (format #t "     -p, --passwd STRING\n")
  (format #t "     -n, --nas IP\n")
  (format #t "     -s, --sid STRING\n")
  (format #t "     -P, --port NUMBER\n"))

;;; Main
;; Load profiles
(load (string-append %raddb-path "/radctl.rc"))
(let ((localrc (string-append (passwd:dir (getpwuid (getuid))) ".radctl")))
  (if (file-exists? localrc)
      (load localrc)))
;; Parse command line
(define cmd-list (getopt-long (command-line) grammar))
(for-each (lambda (x)
	    (and (cons? x)
		 (case (car x)
		   ((port)
		    (set! opt-port (string->number (cdr x))))
		   ((start stop auth help)
		    (set! action (car x)))
		   ((verbose)
		    (set! flag-verbose #t))
		   ((passwd)
		    (set! opt-passwd (if (string=? (cdr x) ".")
					 (rad-read-no-echo "Password: ")
					 (cdr x))))
		   (else
		    (eval (list 'set! (string->symbol
				       (string-append "opt-"
						      (symbol->string (car x))))
				(cdr x)))))))
	  cmd-list)

;; Select and perform appropriate action
(case action
  ((help nil)
   (usage))
  ((auth)
   (check-auth))
  ((start)
   (session-start))
  ((stop)
   (session-stop)))
