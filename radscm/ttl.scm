;;;; This file is part of GNU Radius.
;;;; Copyright (C) 2001,2002,2003 Sergey Poznyakoff
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
;;;; $Id$

;;;; This is a framework for computing the Session-Timeout attribute on
;;;; the fly. The module queries a remote host about a timeout value for
;;;; each user about to login and sets Session-Timeout pair in the user's
;;;; authentication-reply packet. The transport used is UDP. The format
;;;; of query packets is:
;;;;
;;;;  0                   1                   2                   3
;;;;  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;;;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;; |     Length    |      Code     |  User-Name ...                |
;;;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;;
;;;; Length contains the overall length of the packet.
;;;; Code   contains the operation code:
;;;;     ?  Query the remote party about a timeout value
;;;;     +  Notify the remote party about session start for a given user.
;;;;     -  Notify the remote party about session stop.
;;;; User-Name contains a zero-terminated user name.
;;;;
;;;; The reply packet is:
;;;;  0                   1                   2                   3
;;;;  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;;;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;; |     Length    |      Code     |  String...                    |
;;;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;;
;;;; Code is ignored. String contains a timeout value for the user
;;;; converted to ASCII. If it starts with '-', no timeout is set.
;;;;
;;;; usage:
;;;;
;;;; raddb/hints:
;;;; DEFAULT    NULL  Scheme-Acct-Procedure = "ttl-session"
;;;;
;;;; raddb/users:
;;;; BEGIN      NULL  Scheme-Procedure = "ttl-query", Fall-Through = Yes

(use-modules (ice-9 format))

(define ttl-source-ip-address INADDR_ANY)
(define ttl-source-port 0)
(define ttl-dest-ip-address INADDR_ANY)
(define ttl-dest-port 0)
(define ttl-max-retry 1)
(define ttl-timeout 3)

(define (ttl-make-header code user-name)
  (let ((hdr (make-string 2 (integer->char 0))))
    (string-set! hdr 0 (integer->char (+ 3 (string-length user-name))))
    (string-set! hdr 1 code)
    hdr))

(define (ttl-make-packet code user-name)
  (string-append (ttl-make-header code user-name)
                 user-name
                 (make-string 1 (integer->char 0))))

(define (ttl-reply-length packet)
  (char->integer (string-ref packet 0)))

(define (ttl-reply-string packet)
  (substring packet 2 (1- (ttl-reply-length packet))))

(define (ttl-message code user-name)
  (let ((packet (ttl-make-packet code user-name))
        (fd (socket AF_INET SOCK_DGRAM 0))
        (ttl #f))
    (rad-log L_DEBUG (format #f "Sending ~A, ~A" code user-name))
    (cond
     ((not fd)
      (rad-log L_ERR "can't open socket for ttl exchange"))
     (else
      (catch #t
        (lambda ()
          (bind fd AF_INET ttl-source-ip-address ttl-source-port)

          (do ((i 0 (1+ i)))
              ((or ttl (>= i ttl-max-retry)) #f)

              (sendto fd packet AF_INET ttl-dest-ip-address ttl-dest-port)
              (let ((sel (select (list fd) '() '() ttl-timeout)))
                (cond
                 ((not (null? (car sel)))
                  (let* ((ret (recvfrom! fd packet))
                         (length (car ret)))
		    (rad-log L_DEBUG (format #f "length ~A" length))
		    (rad-log L_DEBUG (format #f "reply-length ~A"
					     (ttl-reply-length packet)))
                    (if (not
                         (or
                          (< length 2)
                          (not (= (ttl-reply-length packet) length))))
                        (cond
                         ((or (char=? code #\+) (char=? code #\-))
                          (set! ttl #t)) ;; break from loop
                         (else
                          (cond
                           ((char=? (string-ref (ttl-reply-string packet) 0)
                                      #\-)
                            (set! ttl #t)) ;; Force exit from loop
                           (else
			    (rad-log L_DEBUG (format #f "text ~A"
						     (ttl-reply-string packet)))
                            (let ((num (string->number
                                        (ttl-reply-string packet))))
                              (if (not num)
                                  (begin
                                    (rad-log
                                     L_ERR
                                     (format #f "bad answer \"~A\""
                                             (ttl-reply-string packet)))
                                    (set! ttl 0)))
                                 (set! ttl num) ))))))))))))
        (lambda args
          ;;FIXME: more verbose
          (rad-log L_ERR (format #f "~A" args))))
      (close-port fd)))
    (rad-log L_DEBUG (format #f "returning ~A" ttl))
    ttl))

(define (ttl-query req check reply)
  (let* ((user-pair (assoc "User-Name" req))
         (ttl-pair (assoc "Session-Timeout" reply)))
    (display "ttl-query:")(display user-pair)(display ttl-pair)(newline)
    (cond
     ((not user-pair)
      #f)
     (else
      (let ((ttl (ttl-message #\? (cdr user-pair))))
        (cond
         ((boolean? ttl)
          #t)
         ((= ttl 0)
          (rad-log L_NOTICE
                   (format #f "Zero time to live ~A" (cdr user-pair)))
          (cons
           #f
           (list
            (cons "Reply-Message"
                  "\r\nSorry, your account has expired\r\n"))))
         ((or (not ttl-pair) (< ttl (cdr ttl-pair)))
          (cons #t
                (list
                 (cons "Session-Timeout" ttl))))
         (else
          (rad-log L_NOTICE "Ignoring returned ttl")
          #t)))))))

(define (ttl-session req)
  (let* ((user-pair (assoc "User-Name" req))
         (acct-pair (assoc "Acct-Status-Type" req)))
    (cond
     ((or (not user-pair) (not acct-pair))
      #f)
     ((= (cdr acct-pair) 1) ; Start
      (ttl-message #\+ (cdr user-pair)))
     ((= (cdr acct-pair) 2) ; Stop
      (ttl-message #\- (cdr user-pair)))))
  #t)

;;;; Put any application-specific definifions here:

