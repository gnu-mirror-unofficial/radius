;;; radconf-mode.el --- major mode for editing GNU radius raddb/config file

;; Authors: 2001,2003,2004,2007 Sergey Poznyakoff
;; Version:  1.1
;; Keywords: radius
;; $Id$

;; This file is part of GNU Radius.
;; Copyright (c) 2001,2003,2004,2007 Free Software Foundation, Inc.

;; GNU Radius is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3, or (at your option)
;; any later version.

;; GNU Radius is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Radius; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.

;; Installation.
;;  You may wish to use precompiled version of the module. To create it
;;  run:
;;    emacs -batch -f batch-byte-compile radconf-mode.el
;;  Install files radconf-mode.el and radconf-mode.elc to any directory in
;;  Emacs's load-path.

;; Customization:
;;  To your .emacs or site-start add:
;;  (autoload 'radconf-mode "radconf-mode")
;;  (setq auto-mode-alist (append auto-mode-alist
;;                                '(("raddb/config$" . radconf-mode))))

;; You may also wish to modify the following variables:
;;   radconf-level-indent  -- Amount of indentation per block nesting level.

(eval-when-compile
  ;; We use functions from these modules
  (mapcar 'require '(info)))

(defvar radconf-mode-syntax-table nil
  "Syntax table used in radconf-mode buffers.")

(if radconf-mode-syntax-table
    ()
  (setq radconf-mode-syntax-table (make-syntax-table))
  (modify-syntax-entry ?\# "<" radconf-mode-syntax-table)
  (modify-syntax-entry ?\n " " radconf-mode-syntax-table)
  (modify-syntax-entry ?/  ". 14"  radconf-mode-syntax-table)
  (modify-syntax-entry ?*  ". 23"  radconf-mode-syntax-table)
  (modify-syntax-entry ?\n ">" radconf-mode-syntax-table)
  (modify-syntax-entry ?- "w" radconf-mode-syntax-table)
  (modify-syntax-entry ?_ "w" radconf-mode-syntax-table))

(defvar radconf-mode-abbrev-table
  nil
  "Abbreviation table to use in Radius-Config buffers")

(defvar radconf-mode-map ()
  "Keymap used in Radius-Config buffers.")

(if radconf-mode-map
    ()
  (setq radconf-mode-map (make-sparse-keymap))
  (define-key radconf-mode-map "\t" 'radconf-complete-or-indent)
  (define-key radconf-mode-map "\e\t" 'radconf-indent-command)
  (define-key radconf-mode-map "}" 'radconf-electric-brace)
  (define-key radconf-mode-map "?" 'radconf-describe-keywords) )

(defvar radconf-level-indent 8
  "Amount of additional indentation per nesting level")

;; Find the block opened by one of the keywords from KEYWORD-LIST,
;; such that it contains the point.
(defun radconf-locate-block (&optional keylist)
  (save-excursion
    (beginning-of-line)
    (let ((keyword nil)
          (state (list 'start)))
      (while (and (not (eq (car state) 'stop))
		  (not (bobp))
                  (= (forward-line -1) 0))
        (cond
         ((eq (car state) 'in-comment)
          (if (looking-at "[^#\n]*/\\*$")
              (setq state (cdr state))))
         ((eq (car state) 'in-block)
          (cond
           ((looking-at "\\s *\\w+\\s *\\(\\s \\w+\\s *\\)?{")
            (setq state (cdr state)))
           ((looking-at "[^#\n]*}\\s *;\\s *$")
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
             ((string-match "}\\s *;" string)
              (setq state (append (list 'in-block) state)))
             ((string-match "\\*/" string)
              (if (not (string-match "/\\*" string))
                  (setq state (append (list 'in-comment) state))))
             ((search-forward-regexp "^\\s *\\(\\w+\\)\\s *\\(\\s \\w+\\s *\\)?{" bound t)
	      (let ((word (intern (buffer-substring (match-beginning 1)
						    (match-end 1)))))
		(setq keyword (append (list word) keyword))
		(if (assoc word keylist)
		    (setq state (list 'stop))))))))))
      keyword)))

;; Determine the nesting level of point.
(defun radconf-nesting-level ()
  (length (radconf-locate-block)))
                    
;; Indent current line. Optional LEVEL-OFFSET is subtracted from
;; the determined amount of indentation.
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
  "Indent current line"
  (interactive "p")
  (radconf-indent-line))

;; A list of keywords allowed in each block

(defconst radconf-keyword-dict
  ;; Block     Keyword-list
  '((nil        usedbm
                option
                logging
                auth
                acct
                proxy
                snmp
                guile
		rewrite
		message
		mlc
		filters)
    (option     source-ip 
                max-requests
		max-processes
		process-idle-timeout
		master-read-timeout
		master-write-timeout
		radiusd-user
                exec-program-user
                log-dir
                acct-dir
                resolve
		username-chars)
    (logging    channel
                category
		prefix-hook
		suffix-hook
		(channel    file
			    syslog
			    option
			    prefix-hook
			    suffix-hook
                            print-pid
                            print-category
                            print-cons
                            print-level
                            print-priority
		            print-severity
		            print-milliseconds)
		(category   channel
			    ;; FIXME: These three are allowed
			    ;; only in category auth
		            print-auth  
		            print-failed-pass  
		            print-pass
			    ;; FIXME: level is applicable only
			    ;; in category debug.
			    level))
    (auth       port
                listen
                max-requests
                time-to-live
                request-cleanup-delay
                detail
                strip-names
                checkrad-assume-logged
                password-expire-warning
		compare-atribute-flag
		forward
		trace-rules
		reject-malformed-names
		detail-file-name)
    (acct       port
                listen
                max-requests
                time-to-live
                request-cleanup-delay
		compare-atribute-flag
		forward
		trace-rules
		system
		detail
		detail-file-name)
    (snmp       port
                max-requests
                time-to-live
                request-cleanup-delay
                ident
                community
                network
		(acl        allow
                            deny)
                (storage    file
		            perms
		            max-nas-count
		            max-port-count))
    (mlc        method
		checkrad-assume-logged)
    (guile      debug
                load-path
		load-module
                load
		eval
		outfile
		gc-interval)
    (rewrite	stack-size
		load-path
		load)
    (filters	filter
                (filter     exec-path
		            error-log
		            auth
		            acct
			    (auth input-format
				  wait-reply)
			    (acct input-format
				  wait-reply)))
    (message	account-closed
		password-expired
		password-expire-warning
		access-denied
		realm-quota
		multiple-login
		second-login
		timespan-violation)))

;; Valid successors for keywords.
(defconst radconf-keyword-successor
  ;; Keyword                    List of successors
  '((category                   main auth acct snmp proxy 
                                debug info notice warning error
                                crit emerg alert)
    (detail                     yes no)
    (strip-names                yes no)
    (checkrad-assume-logged     yes no)
    (usedbm                     yes no)
    (print-pid                  yes no)
    (print-category             yes no)
    (print-cons                 yes no)
    (print-level                yes no)
    (print-priority             yes no)
    (print-milliseconds		yes no)
    (print-severity             yes no)
    (print-auth			yes no)
    (print-failed-pass		yes no)
    (print-pass			yes no)
    (system                     yes no)
    (trace-rules                yes no)
    (reject-malformed-names     yes no)))

(defconst radconf-keyword-nodes
  ;; Block kwd  Info file       Info node
  '((nil        "radius"        "config")
    (option     "radius"        "option")
    (logging    "radius"        "logging")
    (auth       "radius"        "auth")
    (acct       "radius"        "acct")
    (notify     "radius"        "notify")
    (snmp       "radius"        "snmp")
    (guile      "radius"        "guile")
    (filters	"radius"	"filters")
    (message	"radius"	"message")
    (rewrite	"radius"	"rewrite")
    (mlc        "radius"        "mlc")))

;; Complete a given keyword
(defun radconf-complete-keyword (word &optional prompt require-match)
  (let ((dict radconf-keyword-dict)
	(kwlist (radconf-locate-block)))
    (while (and kwlist dict (listp dict))
      (let ((kw (car kwlist)))
	(setq kwlist (cdr kwlist))
	(setq dict (assoc kw dict))))
    (if dict
	(let ((compl (completing-read (or prompt "what? ")
				      (mapcar
				       (lambda (x)
					 (cons (symbol-name (if (listp x)
								(car x)
							      x))
							    nil))
				       (cdr dict))
				      nil require-match word nil)))
	  (or compl word)))))

;; Complete the argument to a keyword.
(defun radconf-complete-argument (pred word &optional prompt require-match)
  (let ((table (assoc (intern pred) radconf-keyword-successor)))
    (if table
        (let ((compl (completing-read (or prompt "what? ")
                                      (mapcar
                                       (lambda (x)
                                         (cons (symbol-name (if (listp x)
								(car x)
							      x))
					       nil))
                                       (cdr table))
                                      nil require-match word nil)))
          (or compl word)))))

(defun radconf-complete-or-indent (arg)
  "Complete the keyword the point stays on or indent the current line"
  (interactive "p")
  (let* ((here (point))
         (off 0)
         (bound (save-excursion
                  (beginning-of-line)
                  (point))))
    (if (search-backward-regexp "^\\W*\\(\\w+\\)" bound t)
	(let* ((from (match-beginning 1))
                (to (match-end 1))
                (word (buffer-substring from to)))
          (if (= to here)
              ;; Process a keyword
              (let ((compl (radconf-complete-keyword word "keyword: ")))
                (cond
                 ((and compl (not (string-equal compl word)))
                  (delete-region from to)
                  (goto-char from)
                  (insert compl)
                  (setq off (- (point) here)))))
            ;; Process the argument
            (goto-char to)
            (if (looking-at "\\s *\\(\\w+\\).*$")
                (let* ((from (match-beginning 1))
                       (to (match-end 1))
                       (arg (buffer-substring from to))
                       (compl (radconf-complete-argument
                               word
                               arg
                               "argument: ")))
                  (cond
                   ((and compl (not (string-equal compl arg)))
                    (delete-region from to)
                    (goto-char from)
                    (insert compl)
                    (setq off (- (point) here)))))))
          (goto-char (+ here off)) )
        (radconf-indent-line) )))

(defun radconf-electric-brace (arg)
  "Indent current line and insert a symbol"
  (interactive "p")
  (radconf-indent-line 1)
  (self-insert-command (or arg 1)))

(defun radconf-describe-keywords ()
  "Depending on the context invoke appropriate info page"
  (interactive)
  (let ((block (radconf-locate-block)))
    (if (not block)
	(error "No documentation found")
      (let* ((elt (assoc (car block) radconf-keyword-nodes))
             (file (car (cdr elt)))
             (node (car (cdr (cdr elt)))))
	(Info-goto-node (concat "(" file ")" node))
	(if (get-buffer "*info*")
	    (switch-to-buffer "*info*"))))))

;;;###autoload
(defun radconf-mode ()
  "Major mode for editing GNU Radius raddb/config file.

Key bindings:
\\{radconf-mode-map}
"
  (interactive)
  (kill-all-local-variables)
  (set-syntax-table radconf-mode-syntax-table)
  (make-local-variable 'indent-line-function)
  (setq major-mode 'radconf-mode
        mode-name "Radius-Config"
        local-abbrev-table radconf-mode-abbrev-table
        indent-line-function 'radconf-indent-line
        completion-ignore-case nil)

  (use-local-map radconf-mode-map))

(require 'info) 
(provide 'radconf-mode)
;;; radius-mode ends
