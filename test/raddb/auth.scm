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
	  (display "L:")(display user-data)(newline)
	  (if user-data
	      (call-with-current-continuation
	       (lambda (xx)
		 (for-each
		  (lambda (pair)
		    (cond
		     ((avl-match req (car pair))
		      (set! reply-list (avl-merge reply-list (cdr pair)))
		      (xx #t))))
		  (cdr user-data))
		 #f)))))
    (cons
     #t
     reply-list)))


