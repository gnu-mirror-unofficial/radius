;;; radconf-mode.el --- major mode for editing GNU radius raddb/config file

;; Authors: 2000 Sergey Poznyakoff
;; Version:  1.0
;; Keywords: radius
;; $Id$

;; This file is part of GNU Radius.
;; Copyright (c) 2001, Sergey Poznyakoff

;; GNU Radius is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.

;; GNU Radius is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.

(defvar radconf-mode-syntax-table nil
  "Syntax table used in radconf-mode buffers.")

(if radconf-mode-syntax-table
    ()
  (setq radconf-mode-syntax-table (make-syntax-table))
  (modify-syntax-entry ?\# "<" radconf-mode-syntax-table)
  (modify-syntax-entry ?\n " " radconf-mode-syntax-table)
  (modify-syntax-entry ?/  ". 14"  radconf-mode-syntax-table)
  (modify-syntax-entry ?*  ". 23"  radconf-mode-syntax-table)
  (modify-syntax-entry ?\n ">" radconf-mode-syntax-table) )

(defvar radconf-mode-abbrev-table
  nil
  "Abbreviation table to use in Radius-Config buffers")

(defvar radconf-mode-map ()
  "Keymap used in Radius-Config buffers.")

(if radconf-mode-map
    ()
  (setq radconf-mode-map (make-sparse-keymap))
  (define-key radconf-mode-map "\t" 'radconf-complete-or-self-insert)
  (define-key radconf-mode-map "\e\t" 'radconf-indent-command)
  (define-key radconf-mode-map "}" 'radconf-electric-brace) )

(defconst radconf-toplevel-keywords
  '(option logging auth acct proxy cntl snmp))

(defun radconf-nesting-level ()
  (save-excursion
    (let ((off (if (progn
		     (beginning-of-line)
		     (looking-at "[^#\n]*}.*$"))
		   1
		 0))
	  (level 0)
	  (state (list 'start)))
      (while (and (not (eq (car state) 'stop))
		  (= (forward-line -1) 0))
	(cond
	 ((eq (car state) 'in-comment)
	  (if (looking-at "[^#\n]*/\\*$")
	      (setq state (cdr state))))
	 ((eq (car state) 'in-block)
	  (cond
	   ((looking-at "[^#\n]*{.*$")
	    (setq state (cdr state)))
	   ((looking-at "[^#\n]*}.*$")
	    (setq state (append (list 'in-block) state)))))
	 (t ;; 'start
	  (let* ((bound (save-excursion
			  (end-of-line)
			  (point)))
		 (string (cond
			  ((looking-at "\\([^#\n]*\\)#.*")
			   (buffer-substring (match-beginning 1)
					     (match-end 1)))
			  ((looking-at "\\([^#\n]*\\)//.*")
			   (buffer-substring (match-beginning 1)
					     (match-end 1)))
			  (t
			   (buffer-substring (point) bound)))))
	    (cond
	     ((string-match "}" string)
	      (setq state (append (list 'in-block) state)))
	     ((string-match "/\\*" string)
	      (if (not (string-match "\\*/" string))
		  (setq state (append (list 'in-comment) state))))
	     ((string-match "{" string)
	      (beginning-of-line)
	      (setq level (1+ level))
	      (cond
	       ((search-forward-regexp "\\s *\\w+\\s +\\w+\\s *{" bound t)
		)
	       ((search-forward-regexp "\\s *\\(\\w+\\)\\s *{" bound t)
		(let ((word (intern (buffer-substring (match-beginning 1)
						      (match-end 1)))))
		  (if (and (memq word radconf-toplevel-keywords)
			   (null (cdr state)))
		      (setq state (list 'stop))))))))))))
      (if (> level 0)
	  (- level off)
	level))))
		    
(defvar radconf-level-indent 8)

(defun radconf-indent-line (&optional level-offset)
  (let* ((start-of-line (save-excursion
			  (beginning-of-line)
			  (skip-syntax-forward "\\s *")
			  (point)))
	 (off (- (point) start-of-line))
	 (shift-amt (* radconf-level-indent
		       (-
			(radconf-nesting-level)
			(or level-offset 0)))))
    (if (null shift-amt)
	()
      (beginning-of-line)
      (delete-region (point) start-of-line)
      (indent-to shift-amt))
      (goto-char (+ (point) off))))

(defun radconf-indent-command (arg)
  (interactive "p")
  (radconf-indent-line))

(defconst radconf-keyword-dict
  ;; Block     Keyword-list
  '((nil        usedbm
		option
		logging
		auth
		acct
		proxy
		notify
		snmp)
    (option     source-ip 
		usr2delay
		max-requests
		exec-program-user
		exec-program-group
		log-dir
		acct-dir)
    (logging    channel
		category)
    (channel    file
		syslog
		option)
    (auth       port
		spawn
		max-requests
		time-to-live
		request-cleanup-delay
		detail
		strip-names
		checkrad-assume-logged)
    (acct       port
		spawn
		max-requests
		time-to-live
		request-cleanup-delay)
    (proxy      max-requests
		request-cleanup-delay)
    (notify     host
		port
		retry
		delay)
    (snmp       port
		spawn
		max-requests
		time-to-live
		request-cleanup-delay
		ident
		community
		network
		acl)
    (acl        allow
		deny) ))
	     

(defun radconf-block ()
  (save-excursion
    (if (search-backward "{" nil t)
	(let ((x (search-backward-regexp "[;{]" nil t)))
	  (if (null x)
	      (beginning-of-buffer))
	  (if (search-forward-regexp "\\(\\w+\\)" nil t)
	      (let ((word (intern (buffer-substring (match-beginning 1)
						    (match-end 1)))))
		(if (assoc word radconf-keyword-dict)
		    word)))))))

(defun radconf-complete-keyword (word &optional prompt require-match)
  (let ((table (assoc (radconf-block) radconf-keyword-dict)))
    (if table
	(let ((compl (completing-read (or prompt "what? ")
				      (mapcar
				       (lambda (x)
					 (cons (symbol-name x) nil))
				       (cdr table))
				      nil require-match word nil)))
	  (or compl word)))))


(defun radconf-complete-or-self-insert (arg)
  (interactive "p")
  (let* ((here (point))
	 (bound (save-excursion
		  (beginning-of-line)
		  (point))))
    (if (or (search-backward-regexp "^\\W\\(\\w+\\)" bound t)
	    (search-backward-regexp "^\\(\\w+\\)" bound t))
	(if (= (match-end 1) here)
	    (let* ((from (match-beginning 1))
		   (to (match-end 1))
		   (word (buffer-substring from to))
		   (compl (radconf-complete-keyword word nil t)))
	      (cond
	       ((and compl (not (string-equal compl word)))
		(delete-region from to)
		(goto-char from)
		(insert compl)
		(goto-char (+ (point) (- here to))))
	       (t
		(goto-char here)) ))
	  (goto-char here))
	  (self-insert-command (or arg 1)) )))

(defun radconf-electric-brace (arg)
  (interactive "p")
  (radconf-indent-line 1)
  (self-insert-command (or arg 1)))
	  

;;;###autoload
(defun radconf-mode ()
  "Major mode for editing GNU Radius raddb/config file.

Key bindings:
\\{radconf-mode-map}
"
  (interactive)
  (kill-all-local-variables)
  (set-syntax-table radconf-mode-syntax-table)
  (setq major-mode 'radconf-mode
	mode-name "Radius-Config"
	local-abbrev-table radconf-mode-abbrev-table
	indent-line-function 'radconf-indent-line
	completion-ignore-case nil)

  (use-local-map radconf-mode-map)
  )
  
(provide 'radconf-mode)
;;; radius-mode ends
