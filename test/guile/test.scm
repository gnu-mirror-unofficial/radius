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

(define radius-build-dir "..")
(define radius-source-dir "..")
(define admin-login "ROOT")
(define admin-password "Regnbue")
(define flag-verbose #f)

(define user-list
  ;;   Login        .   Password
  ;;----------------+------------
  '(("claudius"     . "claudius")       
    ("hamlet"       . "hamlet")        
    ("fortinbras"   . "fortinbras")    
    ("polonius"     . "polonius")      
    ("horatio"      . "horatio")       
    ("laertes"      . "laertes")       
    ("voltimand"    . "voltimand")     
    ("cornelius"    . "cornelius")     
    ("rosencrantz"  . "rosencrantz")   
    ("guildenstern" . "guildenstern")  
    ("osric"        . "osric")         
    ("marcellus"    . "marcellus")     
    ("bernardo"     . "bernardo")      
    ("francisco"    . "francisco")     
    ("reynaldo"     . "reynaldo")      
    ("ophelia"      . "ophelia")))      


;;; Some handy functions
(define (message dest . text)
  (for-each (lambda (s)
              (format #t s))
            text)
  (format #t "\n")
  (if dest
      (remark text)))

(define (error text)
  (format #t "ERROR: ~A" text))

(define (cons? p)
  (and (pair? p) (not (list? p))))

(define (dequote s)
  (if (and (char=? (string-ref s 0) #\")
           (char=? (string-ref s (1- (string-length s))) #\"))
      (substring s 1 (1- (string-length s)))
      s))

;;; ====================================================================

(define (rad-auth uname passwd nas port)
  (rad-send :port-auth :auth-req (list (cons "User-Name"  uname)
                                       (cons "Password"  passwd)
                                       (cons "NAS-IP-Address"  nas)
                                       (cons "NAS-Port-Id" port))
            flag-verbose))

(define (rad-acct type uname sid nas port)
  (rad-send :port-acct :acct-req (list (cons "User-Name"  uname)
                                       (cons "Acct-Status-Type"
                                             (rad-dict-name->value
                                              "Acct-Status-Type" type))
                                       (cons "Acct-Session-Id"  sid)
                                       (cons "NAS-IP-Address"  nas)
                                       (cons "NAS-Port-Id" port))
            flag-verbose))

(define (rad-cntl command . cmdlist)
  (case command
    ((getpid)
     (catch 'system-error
       (lambda ()
         (let* ((pidfile (string-append
                          radius-build-dir "/test/log/radiusd.pid"))
                (port (open-file pidfile "r"))
                (line (read-line port)))
           (close port)
           (if (string? line)
               (string->number line)
             #f)))
       (lambda args #f)))
    ((shutdown)
     (let ((pid (rad-cntl 'getpid)))
       (if pid
           (catch 'system-error
             (lambda ()
               (kill pid SIGTERM)
               (sleep 2)
               (cond
                ((rad-cntl 'getpid)
                 (message #f
                  "The daemon did not shut down on TERM signal. Sending KILL")
                 (kill pid SIGKILL))))
             (lambda args
               (message #f "The daemon is not running")
               (exit 1)))
         (message #f "The daemon is not running"))))
    (else
     #f)))

(define (remark rest)
  (rad-cntl 'remark 
            (cond
             ((string? rest)
              (rad-cntl 'remark rest))
             (else
              (let loop ((rest rest)
                         (str ""))
                (cond
                 ((null? rest)
                  str)
                 (else
                  (loop (cdr rest) (string-append str (car rest))))))))))

(define (session-start uname passwd nas port)
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

;;; ====================================================================

(define grammar
  `((verbose)
    (build-dir (value #t))
    (source-dir (value #t)) ))

(for-each (lambda (x)
            (and (cons? x)
                 (case (car x)
                   ((build-dir)
                    (set! radius-build-dir (cdr x)))
                   ((source-dir)
                    (set! radius-source-dir (cdr x)))
                   ((verbose)
                    (set! flag-verbose (not flag-verbose)))  )))
          (getopt-long (command-line) grammar))

;;; Ok, lets get running
;(load (string-append radius-build-dir "/test/raddb/radctl.rc"))

;;; Start radius daemon
(message #f "Starting radius")
(system (string-append radius-build-dir
                       "/radiusd/radiusd"
                       " -d " radius-build-dir "/test/raddb"
                       " -l " radius-build-dir "/test/log"
                       " -a " radius-build-dir "/test/log/acct"
                       " -P " radius-build-dir "/test/log"
                       " -i 127.0.0.1" ))
(sleep 2) ;; Let the things settle.
;;; See if it is running
(cond
 ((not (rad-cntl 'getpid))
  (error "Can't start radius daemon. Abort.")
  (exit 1)))

(define nas-ip-address "127.0.0.1")
(define total-error-count 0)

(define (run-test name descr fun args expect)
  (message #t "============" name ": " descr "============")
  (let ((ec (do ((tail user-list (cdr tail))
                 (port 1 (1+ port))
                 (error-count 0))
                ((null? tail) error-count)
              ;     (format #t "~A\n" (car tail))
              (let* ((pair (car tail))
                     (res (apply fun pair nas-ip-address port args)))
                (if (or (null? res) (not (= (car res) expect)))
                    (set! error-count (1+ error-count)))))))
    (set! total-error-count (+ total-error-count ec))
    (sleep 2)
    (message #t (string-append name ": ")
             (if (= ec 0)
                 "OK"
                 (format #f "~A errors" ec)))))


;;; ======================================================================
;;; Authentication test
(define (test-auth pair nas port)
  (rad-auth (car pair) (cdr pair) nas port))
;;; Accounting test
(define (test-acct pair nas port args)
  (rad-acct args (car pair) (number->string port) nas port))

(run-test "TEST1" "AUTHENTICATION" test-auth '() :auth-ack)
(run-test "TEST2" "ACCOUNTING START" test-acct (list "Start") :acct-resp)
(system "../radwho/radwho -d ./raddb -f ./log/radutmp")
(run-test "TEST3" "ACCOUNTING STOP" test-acct (list "Stop") :acct-resp)
(system "../radlast/radlast -d ./raddb -f ./log/radwtmp")
                               
              
;;; Stop radius daemon
(message #f "Shutting radius down")
(rad-cntl 'shutdown)

(exit total-error-count)

