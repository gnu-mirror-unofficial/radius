;;;; This is a set of Emacs developer tools for GNU Radius.
;;;; Copyright (C) 2004, 2007, 2013 Free Software Foundation
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
;;;; along with GNU Radius.  If not, see <http://www.gnu.org/licenses/>. 

(defun grad-request-name-to-c (name)
  "Convert a request NAME to a valid C request type name"
  (eval (append '(concat "RT")
		(mapcar
		 (function (lambda (x) (concat "_" (upcase x))))
		 (split-string name "-")))))

(defun grad-request-region-to-c (from to)
  "Convert a region of request definitions to a set of corresponding C defines.

Each request definition is a line of the form: REQUEST-NAME REQUEST-NUMBER. See
scripts/request.list for an example.

This function is used to generate RT_ defines in include/radius/radius.h"
  (interactive "*r")
  (save-excursion
    (goto-char from)
    (while (and (not (eobp)) (< (point) to))
      (beginning-of-line)
      (when (looking-at "\\([A-Za-z][A-Za-z0-9_\-]+\\)\\s +\\([0-9]+\\)")
	(let ((name (buffer-substring (match-beginning 1) (match-end 1)))
	      (number (buffer-substring (match-beginning 2) (match-end 2))))
	  (kill-line)
	  (insert "#define "
		  (request-name-to-c name)
		  " "
		  number)))
      (forward-line 1))))

(defun print-conditional (arg stmt-list indent)
  (let ((stmt (car stmt-list)))
    (insert-char ?\  indent)
    (insert "if " arg " == " (car stmt) "\n")
    (insert-char ?\  (1+ indent))
    (insert "echo " (cdr stmt) "\n")
    (cond
     ((cdr stmt-list)
      (insert-char ?\  indent)
      (insert "else\n")
      (print-conditional arg (cdr stmt-list) (1+ indent)))
     (t
      (insert-char ?\  indent)
      (insert "else\n")
      (insert-char ?\  (1+ indent))
      (insert "output " arg "\n")))
    (insert-char ?\  indent)
    (insert "end\n")))

(defun grad-request-region-to-gdb (from to arg)
  "Convert a region of request definitions to a compound GDB expression for
converting request code to request name.

Each request definition is a line of the form: REQUEST-NAME REQUEST-NUMBER. See
scripts/request.list for an example.

This function is used to generate the body of print_reqcode function in
radiusd/.gdbinit"
  (interactive "*r\nsArgument name ($arg0->code): ")
  (save-excursion
    (goto-char from)
    (let ((stmt '()))
      (while (and (not (eobp)) (< (point) to))
	(beginning-of-line)
	(when (looking-at "\\([A-Za-z][A-Za-z0-9_\-]+\\)\\s +\\([0-9]+\\)")
	  (let ((name (buffer-substring (match-beginning 1) (match-end 1)))
		(number (buffer-substring (match-beginning 2) (match-end 2))))
	    (setq stmt (append stmt (list (cons number name))))))
	(forward-line 1))
      (delete-region from to)

      (print-conditional (if (string= "" arg) "$arg0->code" arg) stmt 0))))

;;;; End of radius-devel.el
