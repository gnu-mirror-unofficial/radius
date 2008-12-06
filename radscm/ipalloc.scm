;;;; This file is part of GNU Radius.
;;;; Copyright (C) 2003, 2004, 2007 Free Software Foundation, Inc.
;;;;
;;;; Written by Sergey Poznyakoff
;;;;
;;;; GNU Radius is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 3 of the License, or
;;;; (at your option) any later version.
;;;;
;;;; GNU Radius is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.
;;;;
;;;; You should have received a copy of the GNU General Public License
;;;; along with GNU Radius; if not, write to the Free Software
;;;; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;;;;

;;;; This module implements a "pseudo-static" IP allocation strategy.
;;;; Read doc/README.ipalloc for the complete description.
;;;;
;;;; Usage:
;;;; #raddb/hints:
;;;;  DEFAULT Scheme-Acct-Procedure = "ip-alloc-update"  NULL
;;;; #raddb/users:
;;;;  BEGIN   Scheme-Procedure = "ip-alloc"	Fall-Through = Yes

(define-module (ipalloc)
  :export (ipalloc-max-attempts ipalloc-sleep-time ip-alloc-update ip-alloc)
  :use-module (gnuradius)
  :use-module (radiusd))

;;; Number of lookup retries
(define ipalloc-max-attempts 10)
;;; Time in microseconds between the two subsequent retries.
(define ipalloc-sleep-time 500)

(define (ipalloc-nas->pool nas)
  (let ((pool
	 (radius-sql-query
	  SQL_AUTH
	  (string-append
	   "SELECT pool FROM naspools WHERE nas='" nas "'"))))
    (cond
     ((and pool (not (null? pool)))
      (caar pool))
     (else
      "DEFAULT"))))

(define (ip-alloc req check reply)
  (let ((pool-str (ipalloc-nas->pool
		   (inet-ntoa (cdr (assoc "NAS-IP-Address" req)))))
	(user-name (cdr (assoc "User-Name" req))))
    (radius-sql-query SQL_AUTH
		      (string-append
		       "UPDATE ippool SET status='RSRV',time=current_timestamp"
		       " WHERE user_name='" user-name
		       "' AND pool='" pool-str 
		       "' AND (status='FREE' OR status='RSRV')"))
    (cond
     ((let ((res (radius-sql-query
		  SQL_AUTH
		  (string-append
		   "SELECT ipaddr,status FROM ippool "
		   "WHERE user_name='" user-name
		   "' AND pool='" pool-str
		   "' AND status <> 'BLCK' ORDER BY time"))))
	(cond
	 (res
	  (rad-log GRAD_LOG_DEBUG (string-append "ipalloc " user-name ": HIT"))
	  (car (car res)))
	 (else
	  (rad-log GRAD_LOG_DEBUG (string-append "ipalloc " user-name ": MISS"))
	  (let ((assigned-ip #f))
	    (do ((attempt 0 (1+ attempt)))
		((or assigned-ip (= attempt ipalloc-max-attempts)) assigned-ip)

	      (let ((temp-ip (radius-sql-query
			      SQL_AUTH
			      (string-append
			       "SELECT ipaddr FROM ippool "
			       "WHERE pool='" pool-str
			       "' AND status='FREE'"
			       " ORDER BY time DESC LIMIT 1"))))
		(cond
		 (temp-ip
		  (radius-sql-query
		   SQL_AUTH
		   (string-append
		    "UPDATE ippool SET user_name='" user-name
		    "',status='RSRV',time=current_timestamp"
		    " WHERE ipaddr='" (caar temp-ip)
		    "' AND (status='FREE' OR status='RSRV')"))
		  (if (radius-sql-query
		       SQL_AUTH
		       (string-append
			"SELECT user_name FROM ippool "
			"WHERE (status='RSRV' OR status='ASGN') "
			"AND pool='" pool-str
			"' AND user_name='" user-name "'"))
		      (set! assigned-ip (caar temp-ip))))
		 (else
		  (rad-log GRAD_LOG_ERR "All IPs are busy"))))
	      (usleep ipalloc-sleep-time)))))) =>
	      (lambda (ip)
		(cons
		 #t
		 (list (cons "Framed-IP-Address" ip)))))
     (else
      #f))))

(define (ip-alloc-update req)
  (let ((acct-type (cdr (assoc "Acct-Status-Type" req)))
	(user-name (cdr (assoc "User-Name" req)))
	(pool-str (ipalloc-nas->pool
		   (inet-ntoa (cdr (assoc "NAS-IP-Address" req))))))
    (case acct-type
      ((1) ; Start
       (radius-sql-query
	SQL_AUTH
	(string-append
	 "UPDATE ippool SET time=current_timestamp"
	 ", status='ASGN' WHERE user_name = '" user-name
	 "' AND pool='" pool-str
	 "' AND (status='FREE' OR status='RSRV')")))
      ((2) ; Stop
       (radius-sql-query
	SQL_AUTH
	(string-append
	 "UPDATE ippool SET time=current_timestamp"
	 ", status='FREE' WHERE user_name = '" user-name
	 "' AND pool='" pool-str
	 "' AND (status='ASGN' OR status='RSRV')")))))
  #t)
