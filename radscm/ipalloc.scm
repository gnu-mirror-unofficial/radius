;;;; This file is part of GNU Radius.
;;;; Copyright (C) 2003 Sergey Poznyakoff
;;;;
;;;; GNU Radius is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2 of the License, or
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

;;;; These two functions implement a "pseudo-static" IP allocation strategy.
;;;; The IP pool is kept in a database table of the following structure:
;;;;
;;;; CREATE TABLE ippool (
;;;;  # Current entry status:
;;;;  status enum ('FREE', # Entry is free to use
;;;;               'BLCK', # Entry is blocked and cannot be used
;;;;               'FIXD', # Entry represents a fixed IP address
;;;;               'ASGN', # Entry represents an IP assigned to the user
;;;;               'RSRV') # Entry is reserved
;;;;       default 'FREE' not null,
;;;;  # Timestamp of the last update of the entry
;;;;  time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
;;;;  # A user that is or recently was using this IP
;;;;  user_name varchar(32) binary default '' not null,
;;;;  # NAS IP address
;;;;  nas char(17) default '0.0.0.0' not null 
;;;;  # IP address
;;;;  ipaddr char(17) default '' not null)
;;;;
;;;;  Usage:
;;;;  #raddb/hints:
;;;;  DEFAULT Scheme-Acct-Procedure = "ip-alloc-update"  NULL
;;;;  #raddb/users
;;;;  BEGIN   Scheme-Procedure = "ip-alloc"	Fall-Through = Yes

;; Define this to 'postgres if you use PostgreSQL. For other DBMS you will
;; have to modify the *abstime* definition below.
(define dbtype 'mysql)
(define *abstime* (case dbtype
		    ((mysql) "unix_timestamp()")
		    ((postgres) "abstime('now')")
		    (else
		     (error (string-append
			     (port-filename (current-input-port)) ":"
			     (number->string (port-line (current-input-port)))
			     " "
			     "unknown SQL interface")))))

(define (ip-alloc req check reply)
  (let ((nas-ip (inet-ntoa (cdr (assoc "NAS-IP-Address" req))))
	(user-name (cdr (assoc "User-Name" req))))
    (radius-sql-query SQL_AUTH
		      (string-append
		       "UPDATE ippool "
		       "SET status='RSRV',time=" *abstime* ",nas='"
		       nas-ip
		       "' WHERE user_name='" user-name
		       "' AND (status='FREE' OR status='RSRV')"))
    (cond
     ((let ((res (radius-sql-query
		  SQL_AUTH
		  (string-append
		   "SELECT ipaddr,status FROM ippool WHERE user_name='"
		   user-name "' AND status <> 'BLCK'"))))
	(cond
	 (res
	  (rad-log L_DEBUG "HIT")
	  (car (car res)))
	 (else
	  (rad-log L_DEBUG "MISS")
	  (let ((assigned-ip #f))
	    (do ((attempt 0 (1+ attempt)))
		((or assigned-ip (= attempt 10)) assigned-ip)

	      (let ((temp-ip (radius-sql-query
			      SQL_AUTH
			      (string-append
			       "SELECT ipaddr FROM ippool\
 WHERE status='FREE' ORDER BY time LIMIT 1"))))
		(cond
		 (temp-ip
		  (radius-sql-query
		   SQL_AUTH
		   (string-append
		    "UPDATE ippool SET user_name='" user-name
		    "',status='RSRV',time=" *abstime* ",nas='"
		    nas-ip "' WHERE ipaddr='" (caar temp-ip)
		    "' AND (status='FREE' OR status='RSRV')"))
		  (if (radius-sql-query
		       SQL_AUTH
		       (string-append
			"SELECT user_name FROM ippool \
WHERE (status='RSRV' OR status='ASGN') AND user_name='" user-name "'"))
		      (set! assigned-ip (caar temp-ip))))
		 (else
		  (rad-log L_ERR "All IPs are busy"))))
	      (usleep 500)))))) =>
	      (lambda (ip)
		(cons
		 #t
		 (list (cons "Framed-IP-Address" ip)))))
     (else
      #f))))

(define (ip-alloc-update req)
  (let ((acct-type (cdr (assoc "Acct-Status-Type" req)))
	(user-name (cdr (assoc "User-Name" req))))
    (case acct-type
      ((1) ; Start
       (radius-sql-query
	SQL_AUTH
	(string-append
	 "UPDATE ippool SET time=" *abstime*
	 ", status='ASGN' WHERE user_name = '"
	 user-name "' AND (status='FREE' OR status='RSRV')")))
      ((2) ; Stop
       (radius-sql-query
	SQL_AUTH
	(string-append
	 "UPDATE ippool SET time=" *abstime*
	 ", status='FREE' WHERE user_name = '"
	 user-name "' AND (status='ASGN' OR status='RSRV')")))))
  #t)
