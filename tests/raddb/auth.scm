;;;; This file is part of GNU Radius testsuite.
;;;; Copyright (C) 2001,2003,2008 Free Software Foundation, Inc.
;;;;
;;;; Written by Sergey Poznyakoff
;;;;
;;;; This file is free software; as a special exception the author gives
;;;; unlimited permission to copy and/or distribute it, with or without
;;;; modifications, as long as this notice is preserved.
;;;;
;;;; GNU Radius is distributed in the hope that it will be useful, but
;;;; WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
;;;; implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

(define staff-data
  (list
   (list "scheme"
         (cons
          (list (cons "NAS-IP-Address" "127.0.0.1"))
          (list (cons "Framed-MTU" "8096")))
         (cons
          '()
          (list (cons "Framed-MTU" "256"))))))
  
(define (auth req check reply)
  (let* ((username (assoc "User-Name" req))
         (reqlist (assoc username req))
         (reply-list '()))
    (if username
        (let ((user-data (assoc (cdr username) staff-data)))
          (rad-log GRAD_LOG_INFO (format #f "~A" user-data))
          (if user-data
              (call-with-current-continuation
               (lambda (xx)
                 (for-each
                  (lambda (pair)
                    (cond
                     ((avl-match? req (car pair))
                      (set! reply-list (avl-merge reply-list (cdr pair)))
                      (xx #t))))
                  (cdr user-data))
                 #f)))))
    (cons
     #t
     reply-list)))


