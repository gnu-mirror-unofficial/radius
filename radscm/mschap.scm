;;;; This file is part of GNU Radius.
;;;; Copyright (C) 2004, 2007 Free Software Foundation, Inc.
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

(define-module (mschap)
  :use-module (radiusd)
  :use-module (gnuradius))

(define (get-attr name pairlist)
  (cond
   ((assoc name pairlist) =>
    (lambda (x)
      (cdr x)))
   (else
    #f)))

(define (smb-ctrl-set? pair char)
  (and pair (string-index (cdr pair) char)))

(define (get-lm-pass pairlist)
  (cond
   ((get-attr "LM-Password" pairlist) =>
    (lambda (pass)
      (if (or (= (string-length pass) 16)
	      (= (string-length pass) 32))
	  (string-hex->bin pass)
	  (begin
	    (grad-log GRAD_LOG_ERR (_"Invalid LM-Password"))
	    #f))))
   ((get-attr "User-Password" pairlist) =>
    (lambda (user-pass)
      (substring (lm-password-hash user-pass) 0 16)))
   (else
    (grad-log GRAD_LOG_ERR
	      (_"Cannot create LM-Password: User-Password is not present."))
    #f)))

(define (nt-password-hash pass)
  "Insert a null character every other byte, thereby emulating M$ brain-damaged
notion about Unicode, then produce an MD4 hash of the resulting string"
  (md4-calc (list->string
	     (apply
	      append
	      (map
	       (lambda (a)
		 (list a #\nul))
	       (string->list pass))))))

(define (get-nt-pass pairlist)
  (cond
   ((get-attr "NT-Password" pairlist) =>
    (lambda (pass)
      (if (or (= (string-length pass) 16)
	      (= (string-length pass) 32))
	  (string-hex->bin pass)
	  (begin
	    (grad-log GRAD_LOG_ERR (_"Invalid NT-Passwors"))
	    #f))))
   ((get-attr "User-Password" pairlist) =>
    (lambda (x)
      (nt-password-hash x)))
   (else
    (grad-log GRAD_LOG_ERR
	      (_"Cannot create NT-Password: User-Password is not present."))
    #f)))

(define (ms-chap-1 pass challenge response offset)
  (if (not (string=? (mschap-response pass challenge)
		     (substring response offset)))
      (auth-failure (_ "MS-CHAP-Response is incorrect"))))

(define (challenge-hash peer-chlg auth-chlg user-name)
  (substring (sha1-calc (substring peer-chlg 0 16)
			(substring auth-chlg 0 16)
			user-name)
	     0 8))

(define (ms-chap-2-response peer-chlg auth-chlg user-name nt-pass)
  (mschap-response nt-pass (challenge-hash peer-chlg auth-chlg user-name)))

(define magic1
  (list->string
   (map
    integer->char
    (list
     #x4D #x61 #x67 #x69 #x63 #x20 #x73 #x65 #x72 #x76
     #x65 #x72 #x20 #x74 #x6F #x20 #x63 #x6C #x69 #x65
     #x6E #x74 #x20 #x73 #x69 #x67 #x6E #x69 #x6E #x67
     #x20 #x63 #x6F #x6E #x73 #x74 #x61 #x6E #x74))))
  
(define magic-2
  (list->string
   (map
    integer->char
    (list
     #x50 #x61 #x64 #x20 #x74 #x6F #x20 #x6D #x61 #x6B
     #x65 #x20 #x69 #x74 #x20 #x64 #x6F #x20 #x6D #x6F
     #x72 #x65 #x20 #x74 #x68 #x61 #x6E #x20 #x6F #x6E
     #x65 #x20 #x69 #x74 #x65 #x72 #x61 #x74 #x69 #x6F
     #x6E))))

(define (generate-authenticator-response
	 user-name nt-pass nt-resp peer-chlg auth-chlg)
  (string-append "S="
		 (string-bin->hex
		  (sha1-calc
		   (sha1-calc
		    (substring (md4-calc nt-pass) 0 16)
		    (substring nt-resp 0 24)
		    magic-1)
		   (challenge-hash peer-chlg auth-chlg user-name)
		   magic-2))))

(define (auth-failure reason . reply-pairs)
  (if reason
      (rad-log GRAD_LOG_ERR reason))
  (apply throw
	 (append
	  (list 'auth-failure)
	  reply-pairs)))

(define (auth-success reason . reply-pairs)
  (if reason
      (rad-log GRAD_LOG_NOTICE reason))
  (apply throw
	 (append
	  (list 'auth-success)
	  reply-pairs)))

(define (auth-handler req check reply)
  (let ((smb-ctrl (assoc "SMB-Account-CTRL" check)))
    (if (smb-ctrl-set? smb-ctrl #\N)
	#t
	(let ((lm-pass (get-lm-pass check))
	      (nt-pass (get-nt-pass check)))
	  (cond
	   ((and (not lm-pass) (not nt-pass))
	    (auth-failure
	     (_ "MS-CHAP authentication failed: no LM-Password or NT-Password attribute found.")))
	   ;; If User-Password is provided, check if it matches LM-Password
	   ;; or NT-Password
	   ((get-attr "User-Password" req) =>
	    (lambda (user-pass)
	      (cond
	       (lm-pass
		(cond
		 ((string=? (substring (lm-password-hash user-pass) 0 16)
			    lm-pass)
		  (rad-log GRAD_LOG_DEBUG "User-Password matches LM-Password")
		  #t)
		 (else
		  (rad-log GRAD_LOG_DEBUG
			   "User-Password does not match LM-Password")
		  (auth-failure #f))))
	       (nt-pass
		(cond
		 ((string=? (nt-password-hash user-pass)
			    lm-pass)
		  (rad-log GRAD_LOG_DEBUG "User-Password matches NT-Password")
		  (auth-success #f))
		 (else
		  (rad-log GRAD_LOG_DEBUG
			   "User-Password does not match NT-Password")
		  (auth-failure #f))))
	       (else
		(auth-failure #f))))) ; Should not happen
	   
	   ;; Otherwise, we should have MS-CHAP-Challenge
	   ((get-attr "MS-CHAP-Challenge" req) =>
	    (lambda (challenge)
	      (cond
	       ((get-attr "MS-CHAP-Response" req) =>
		(lambda (response)
		  (if (< (string-length challenge 8))
		      (auth-failure (_ "MS-CHAP-Challenge is malformed")))

		  (if (< (string-length response 50))
		      (auth-failure (_ "MS-CHAP-Response is malformed")))

		  (cond
		   ((= (logand (char->integer (string-ref response 1)) 1) 1)
		    (rad-log GRAD_LOG_DEBUG "Using NT-Password for MS-CHAPv1")
		    (ms-chap-1 nt-pass challenge response 26))
		   (else
		    (rad-log GRAD_LOG_DEBUG "Using LM-Password for MS-CHAPv1")
		    (ms-chap-1 lm-pass challenge response 26)))))

	       ((get-attr "MS-CHAP2-Response" req) =>
		(lambda (response)
		  (if (< (string-length challenge 16))
		      (auth-failure (_ "MS-CHAP-Challenge is malformed")))

		  (if (< (string-length response 50))
		      (auth-failure (_ "MS-CHAP-Response is malformed")))

		  (let ((user-name (get-attr "User-Name" req)))
		    (if (not user-name)
			(auth-failure
			 (_ "User-Name is missing in the request (required by MS-CHAPv2)")))
		    (if (not nt-pass)
			(auth-failure
			 (_ "NT-Password is not configured (required by MS-CHAPv2)")))
		    
		    (let ((exp (ms-chap-2-response
				(substring response 2)
				challenge
				nt-pass)))
		      (cond
		       ((string=? (substring response 26) exp)
			;; OK
			(set! reply (append
				     reply
				     (cons "MS-CHAP2-Success"
					   (generate-authenticator-response
					    user-name
					    exp
					    (substring response 2)
					    challenge)))))
		       (else
			(auth-failure (_ "MS-CHAP2-Response is incorrect")
				   (cons "MS-CHAP-Error" "E=691 R=1"))))))))
	       (else
		(auth-failure (_ "No MS-CHAP response found") #f)))))
	   
	   (else
	    (auth-failure (_ "No MS-CHAP-Challenge in the request"))))

	  ;; We are here if CHAP authentication succeeded

	  (if smb-ctrl
	      (cond
	       ((or (smb-ctrl-set? smb-ctrl #\D)
		    (not (smb-ctrl-set? smb-ctrl #\U)))
		(auth-failure
		 (_ "Account is disabled or is not a normal user account")
		 (cons "MS-CHAP-Error" "E=691 R=1")))
	       ((smb-ctrl-set? smb-ctrl #\L)
		(auth-failure
		 (_ "Account is locked out")
		 (cons "MS-CHAP-Error" "E=647 R=0")))))

	  ;; FIXME: Create MPPE attributes
	  

	  ;; Everythng is passed OK. Acknowledge log-in and return the reply
	  ;; pairs.
	  (cons #t reply)))))

	      
(define (auth req check reply)
  (catch 'auth-failure
	 (lambda ()
	   (catch 'auth-success
		  (lambda ()
		    (auth-handler req check reply))
		  (lambda (key . args)
		    (if (null? args)
			#t
			(cons #t args)))))
	 (lambda (key . args)
	   (if (null? args)
	       #f
	       (cons #f args)))))

;; Bootstrap code
(radiusd-register-auth-method "MS-CHAP" auth)

;;;; End of mschap.scm
