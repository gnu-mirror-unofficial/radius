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

(define radius-source-dir "..")
(define admin-login "ROOT")
(define admin-password "Regnbue")
(define flag-verbose #f)

(define user-list
  '(("claudius"     . "claudius")       
    ("hamlet"	    . "hamlet")        
    ("fortinbras"   . "fortinbras")    
    ("polonius"	    . "polonius")      
    ("horatio"	    . "horatio")       
    ("laertes"	    . "laertes")       
    ("voltimand"    . "voltimand")     
    ("cornelius"    . "cornelius")     
    ("rosencrantz"  . "rosencrantz")   
    ("guildenstern" . "guildenstern")  
    ("osric"	    . "osric")         
    ("marcellus"    . "marcellus")     
    ("bernardo"	    . "bernardo")      
    ("francisco"    . "francisco")     
    ("reynaldo"	    . "reynaldo")      
    ("ophelia"      . "ophelia")))      


;;; Some handy functions
(define (message . text)
  (for-each (lambda (s)
	      (format #t s))
	    text)
  (format #t "\n"))

(define (error text)
  (format #t "ERROR: ~A" text))

(define (cons? p)
  (and (pair? p) (not (list? p))))

;;; ====================================================================

(define (rad-auth uname passwd nas port)
  (rad-send :port-auth :auth-req (list (cons "User-Name"  uname)
				       (cons "Password"  passwd)
				       (cons "NAS-IP-Address"  nas)
				       (cons "NAS-Port-Id" port))
	    flag-verbose))

(define (rad-acct uname acct-type nas port sid . plist)
  (let ((pack (list (cons "User-Name"  uname)
		    (cons "Acct-Status-Type" (if (string? acct-type)
						 (rad-dict-name->value
						  "Acct-Status-Type" acct-type)
						 acct-type))
		    (cons "Acct-Session-Id" sid)
		    (cons "NAS-Port-Id" port))))
    (rad-send :port-acct :acct-req
	      (cond
	       ((pair? plist)
		(append pack (car plist)))
	       (else
		pack))
	      flag-verbose)))

(define (rad-cntl command . cmdlist)
  (let* ((state (symbol->string command))
	 (pack (list (cons "User-Name"  admin-login)
		     (cons "Password"  admin-password)
		     (cons "State" state))))
    (let ((ans (rad-send :port-cntl :auth-req
			 (if (null? cmdlist)
			     pack
			     (append pack (list (cons "Class" (car cmdlist)))))
			 flag-verbose)))
      (cond
       ((null? ans)
	(format #t "FAILED\n")
	#f)
       (else
	(if (= (car ans) :auth-ack)
	    (format #t "OK\n")
	    (format #t "ERROR\n"))
	(rad-format-reply-msg (cdr ans))
	(format #t "\n")
	#t)))))

(define (session-start uname passwd nas port sid)
  (let ((auth (rad-auth uname passwd nas port)))
    (let loop ((auth auth))
      (cond
       ((null? auth)
	(format #t "Authentication failed\n")
	#f)
       (else
	(cond
	 ((= (car auth) :auth-ack)
	  (let ((acct (rad-acct uname "Start" nas port sid (cdr auth))))
	    (cond
	     ((null? acct)
	      (format #t "Accounting failed\n")
	      #f)
	     (else
	      (cond 
	       ((= (car acct) :acct-resp)
		(format #t "Accounting OK\n")
		#t)
	       (else
		(format #t "Accounting failed: response ~A\n"
			(rad-format-code #f (car acct)))
		(rad-format-reply-msg (cdr auth) "Reply Message:")
		#f))))))
	 ((= (car auth) :auth-rej)
	  (format #t "Authentication failed\n")
	  (rad-format-reply-msg (cdr auth) "Reply Message:")
	  #f)
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
	  (rad-format-reply-msg (cdr auth) "Reply Message:")
	  #f)))))))

;;; ====================================================================

(define grammar
  `((source-dir (value #t))
    (build-dir (value #t)) ))

(for-each (lambda (x)
	    (and (cons? x)
		 (case (car x)
		   ((source-dir)
		    (set! radius-source-dir (cdr x)))
		   ((verbose)
		    (set! flag-verbose (not flag-verbose)))  )))
	  (getopt-long (command-line) grammar))

;;; Fix-up the paths
(if (char=? (string-ref radius-source-dir 0) #\.)
    (set! radius-source-dir (string-append (getcwd) "/" radius-source-dir)))

;;; Ok, lets get running
(load (string-append radius-source-dir "/test/raddb/radctl.rc"))

;;; Start radius daemon
(message "Starting radius")
(system (string-append radius-source-dir
		       "/radiusd/radiusd"
		       " -d " radius-source-dir "/test/raddb"
		       " -l " radius-source-dir "/test/log"
		       " -a " radius-source-dir "/test/acct"))
;;; Test if it is running
(cond
 ((not (rad-cntl 'getpid))
  (error "Can't start radius daemon. Abort.")
  (exit)))

(define nas-ip-address "127.0.0.1")

(define total-error-count 0)

;;; ======================================================================
;;; Authentication test
(message "============== TEST1: AUTHENTICATION ==============")

(let ((ec (do ((tail user-list (cdr tail))
	       (port 1 (1+ port))
	       (error-count 0))
	      ((null? tail) error-count)
;	    (format #t "~A\n" (car tail))
	    (let* ((pair (car tail))
		   (auth (rad-auth (car pair) (cdr pair)
				   nas-ip-address port)))
	      (if (null? auth)
		  (set! error-count (1+ error-count)))))))
  (set! total-error-count (+ total-error-count ec))
  (message "TEST1: "(if (= ec 0)
			"OK"
			(format #f "~A errors\n" ec))))

;;; ======================================================================
;;; Accounting test
(message "============== TEST2: ACCOUNTING ==================")
(let ((ec (do ((tail user-list (cdr tail))
	       (port 1 (1+ port))
	       (error-count 0))
	      ((null? tail) error-count)
	    (let ((pair (car tail)))
	      (if (not (session-start (car pair) (cdr pair)
				      nas-ip-address port
				      (format #f "~A" port)))
		  (set! error-count (1+ error-count)))))))
  (set! total-error-count (+ total-error-count ec))
  (message "TEST2: "(if (= ec 0)
			"OK"
			(format #f "~A errors\n" ec))))

		
	       
	      
;;; Stop radius daemon
(message "Shutting radius down")
(rad-cntl 'shutdown)

(exit total-error-count)