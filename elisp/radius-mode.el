;;; radius-mode.el --- major mode for editing GNU radius configuration files

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

;; Installation.
;;  You may wish to use precompiled version of the module. To create it
;;  run:
;;    emacs -batch -f batch-byte-compile radius-mode.el
;;  Install files radius-mode.el and radius-mode.elc to any directory in
;;  Emacs's load-path.

;; Customization:
;;  To your .emacs or site-start add:
;;  (autoload 'radius-mode "radius-mode")
;;  (setq radius-db-path <path-to-raddb-directory>)
;;  (setq auto-mode-alist (append auto-mode-alist
;;                                '(("raddb/users$" . radius-mode)
;;                                  ("raddb/hints$" . radius-mode)
;;                                  ("raddb/huntgroups$" . radius-mode))))

;; You may also wish to modify the following variables:
;;   radius-initial-pair-indent -- Amount of indentation for the first A/V
;;                                 pair in the list.
;;   radius-cont-pair-indent    -- Additional amount of indentation for the
;;                                 subsequent A/V pairs in the list.

(defvar rad-mode-syntax-table nil
  "Syntax table used in radius-mode buffers.")
(if rad-mode-syntax-table
    ()
  (setq rad-mode-syntax-table (make-syntax-table))
  (modify-syntax-entry ?\# "<" rad-mode-syntax-table)
  (modify-syntax-entry ?\n ">" rad-mode-syntax-table)
  (modify-syntax-entry ?\t "-" rad-mode-syntax-table)
  (modify-syntax-entry ?- "w" rad-mode-syntax-table))

(defvar rad-mode-abbrev-table nil
  "Abbrev table in use in rad-mode buffers.")

(define-abbrev-table 'rad-mode-abbrev-table
  '(("DE" "DEFAULT " nil 0)
    ("BE" "BEGIN " nil 0)) )
	
(defvar rad-mode-map ()
  "Keymap used in radius-mode buffers.")

(if rad-mode-map
    ()
  (setq rad-mode-map (make-sparse-keymap))
  (define-key rad-mode-map "=" 'rad-electric-equal)
  (define-key rad-mode-map "," 'rad-electric-comma)
  (define-key rad-mode-map "\t" 'rad-indent-command) )


(defconst rad-re-value "\\(\\w\\|\\s\"\\|\\.\\)+"
  "regular expression representing value part of an A/V pair")
(defconst rad-re-attrname "\\w+"
  "regular expression representing attribute name")
(defconst rad-re-pair (concat rad-re-attrname
			      "\\s *=\\s *"
			      rad-re-value)
  "regular expression representing an A/V pair")
  

;; Guess syntax context of the current line. Return a cons whose car
;; is the current syntax and cdr -- number of lines we needed to
;; read back to determine it.
(defun rad-guess-syntax ()
  (save-excursion
    (beginning-of-line)
    (cond
     ((looking-at "\\s *#")
      (cons 'rad-comment 0))
     ((or
       (looking-at (concat "\\w+\\s +" rad-re-pair ","))
       (looking-at (concat "\\w+\\s +" rad-re-pair )))
      (cons 'rad-defn 0))	
     (t
      (let ((syntax nil)
	    (count 0))
	(while (and (null syntax) (> (point) 1))
	  (forward-line -1)
	  (setq count (1+ count))
	  (cond
	   ((looking-at (concat "\\w+\\s +" rad-re-pair ",\\s *$"))
	    (setq syntax 'rad-check-pair))
	   ((looking-at (concat "\\w+\\s +.*" rad-re-pair "\\s *$"))
	    (setq syntax 'rad-reply-pair))
	   ((or
	     (looking-at (concat "\\s *" rad-re-pair "\\s *$"))
	     (looking-at (concat "\\s *" rad-re-pair "\\s *#.*$")))
	    (setq syntax
		  (if (eq (car (rad-guess-syntax)) 'rad-check-pair)
			  'rad-reply-pair
		    'rad-defn)))))
	(cons (or syntax 'rad-defn) count))))))

(defun rad-bol ()
  (beginning-of-line)
  (search-forward-regexp "\\s *" nil t))

(defvar radius-initial-pair-indent 8)
(defvar radius-cont-pair-indent 8)

(defun rad-indent-line (&optional syntax)
  (let* ((off (save-excursion
		(let ((p (point)))
		  (save-excursion
		    (rad-bol)
		    (- p (point))))))
	 (sc (or syntax (rad-guess-syntax)))
	 (s (car sc))
	 (l (cdr sc))
	 (start-of-line (rad-bol)))
    (let* ((cur-point (point))
	   (shift-amt (cond
		       ((eq s 'rad-comment)
			0) ;; FIXME?: edit to the previous comment indent level
		       ((eq s 'rad-check-pair)
			(+ radius-initial-pair-indent
			   (if (= l 0)
			       0
			     radius-cont-pair-indent)))
		       ((eq s 'rad-reply-pair)
			(+ radius-initial-pair-indent
			   (if (= l 1)
			       0
			     radius-cont-pair-indent)))
		       ((eq s 'rad-defn)
			0)
		       (t
			nil))))
      (if (null shift-amt)
	  ()
	(beginning-of-line)
	(delete-region (point) start-of-line)
	(indent-to shift-amt)))
    (goto-char (+ (point) off))))

(defun rad-indent-command (arg)
  (interactive "p")
  (rad-indent-line))

(defvar rad-attr-dict nil)
(defvar rad-value-dict nil)

;; Read radius dictionary located at PATH.
(defun rad-read-dictionary (path)
  (let ((buf (find-file-noselect path)))
    (save-excursion
      (set-buffer buf)
      (set-syntax-table rad-mode-syntax-table)
      (beginning-of-buffer)
      (while (< (point) (point-max))
	(cond
	 ((looking-at "\\s *\$INCLUDE\\s +\\([a-zA-Z0-9.,_\-+]+\\)")
	  (rad-read-dictionary (concat radius-db-path "/"
				       (buffer-substring (match-beginning 1)
							 (match-end 1)))))
	 ((looking-at "ATTRIBUTE\\s +\\(\\w+\\)\\s +\\([0-9]+\\)\\s +\\(\\w+\\)")
	  (let ((data (match-data)))
	    (setq rad-attr-dict (append
				 rad-attr-dict
				 (list
				  (list
				   (buffer-substring (nth 2 data)
						     (nth 3 data))
				   (string-to-number
				    (buffer-substring (nth 4 data)
						      (nth 5 data)))
				   (buffer-substring (nth 6 data)
						     (nth 7 data))))))))
	 ((looking-at "VALUE\\s +\\(\\w+\\)\\s +\\(\\w+\\)\\s +\\([0-9]+\\)")
	  (let* ((data (match-data))
		 (attr (buffer-substring (nth 2 data)
					 (nth 3 data)))
		 (value (buffer-substring (nth 4 data)
					  (nth 5 data)))
		 (intval (string-to-number
			  (buffer-substring (nth 6 data)
					    (nth 7 data))))
		 (alist (assoc attr rad-value-dict)))
	    (if alist
		(setcdr alist (append (list
				       (list value intval))
				      (cdr alist)))
	      (setq rad-value-dict (append (list
					    (cons
					     attr
					     (list
					      (list value intval))))
					   rad-value-dict))) )))
	(forward-line)))
    (kill-buffer buf)))

(defun rad-complete (regexp dict &optional select prompt c)
  (let ((here (point)))
    (if (search-backward-regexp regexp nil t)
	(let* ((from (match-beginning 1))
	       (to (match-end 1))
	       (attr (buffer-substring from to))
	       (str (if (not (assoc attr dict))
			(let ((compl (completing-read (or prompt "what? ")
						      (if select
							  (funcall select
								   dict)
							dict)
						      nil nil attr nil)))
			  (if compl
			      compl
			    attr))
		      attr)))
	  (cond
	   ((and str (not (string-equal str attr)))
	    (delete-region from to)
	    (goto-char from)
	    (insert str)
	    (goto-char (+ (point) (- here to))))
	   (t
	    (goto-char here))) )))
  (and c (insert c)) )

(defun rad-electric-equal (arg)
  (interactive "p")
  (rad-complete "\\W\\(\\w+\\)\\s *" rad-attr-dict nil "attribute: " ?=))

(defun rad-select-attr-values (dict)
  (save-excursion
    (forward-char)
    (if (search-backward-regexp "\\W\\(\\w+\\)\\s *=")
	(let* ((attr (buffer-substring (match-beginning 1)
				       (match-end 1)))
	       (alist (assoc attr dict)))
	  (if alist
	      (cdr alist)
	    nil))
      nil)))

(defun rad-electric-comma (arg)
  (interactive "p")
  (rad-complete "=\\s *\\(\\w+\\)" rad-value-dict
		'rad-select-attr-values "value: " ?,))

(defvar radius-db-path "/usr/local/etc/raddb")

;;;###autoload
(defun radius-mode ()
  "Major mode for editing GNU Radius configuration files: users, hints,
and huntgroups.

Key bindings:
\\{rad-mode-map}
"
  (interactive)
  (kill-all-local-variables)
  (set-syntax-table rad-mode-syntax-table)
  (setq major-mode 'radius-mode
	mode-name "Radius"
	local-abbrev-table rad-mode-abbrev-table
	indent-line-function 'rad-indent-line)

  (use-local-map rad-mode-map)
  (if (null rad-attr-dict)
	(rad-read-dictionary (concat radius-db-path "/dictionary"))))
  
(provide 'radius-mode)
;;; radius-mode ends

