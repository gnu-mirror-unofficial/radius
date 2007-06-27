;;; rewrite-mode.el --- major mode for editing GNU radius Rewrite sources

;; Authors: 2004, 2007 Sergey Poznyakoff
;; Version:  1.0
;; Keywords: radius
;; $Id$

;; This file is part of GNU Radius.
;; Copyright (c) 2004, 2007 Free Software Foundation, Inc.

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

;; Customization:
;;  To your .emacs or site-start add:
;;  (autoload 'rewrite-mode "rewrite-mode")
;;  (setq auto-mode-alist (append auto-mode-alist
;;                                '((".*\.rw$" . rewrite-mode))))

(defconst rewrite-font-lock-keywords
  (eval-when-compile
    (list
     ;;
     ;; Function names.
     '("^[ \t]*\\(string|integer\\)\\>[ \t]*\\(\\sw+\\)?"
       (1 font-lock-keyword-face) (2 font-lock-function-name-face nil t))
     ;;
     ;; Variable names.
     (cons "%\\\[[[:word:]\\-]+\\\]" 'font-lock-variable-name-face)

     ;;
     ;; Keywords.
     (regexp-opt
      '("if" "else" "return" "for" "do" "while" "break" "continue"
	"delete" "string" "integer") 'words)
     ;;
     ;; Builtins.
     (list (regexp-opt
	    '("length" "index" "rindex" "substr" "logit" "field"
	      "ntohl" "htonl" "ntohs" "htons" "inet_ntoa" "inet_aton"
	      "sub" "gsub" "qprn" "tolower" "toupper" "unquote_string"
	      "quote_string" "request_code_string" "gettext" "_" "dgettext"
	      "ngettext" "dngettext" "textdomain" "request_source_ip"
	      "request_source_port" "request_id" "request_code" "nas_name"
	      "nas_short_name" "nas_full_name" "gethostbyaddr"
	      "gethostbyname") 'words)
	   1 'font-lock-builtin-face)
     ;;
     ;; Operators.
     (cons (regexp-opt '("&&" "||" "<=" "<" ">=" ">" "==" "!=" "!~" "=~"))
	   'font-lock-constant-face) ))
  "Default expressions to highlight in Rewrite mode.")


;;;###autoload
(define-derived-mode rewrite-mode c-mode "Rewrite"
    "Major mode for editing GNU Radius Rewrite source files.
This is much like C mode except for the syntax of comments. Its keymap
inherits from C mode's and it has the same variables for customizing
indentation.  

  Key bindings:
\\{rewrite-mode-map}"

    (modify-syntax-entry ?\n "> b" rewrite-mode-syntax-table)
    (modify-syntax-entry ?\# "< 1b" rewrite-mode-syntax-table)
    (modify-syntax-entry ?\040 " 2b" rewrite-mode-syntax-table)

    (set (make-local-variable 'comment-start) "# ")
    (set (make-local-variable 'comment-end) "")
    (set (make-local-variable 'comment-start-skip) "#+ *")
    (setq font-lock-defaults
	  '(rewrite-font-lock-keywords nil nil ((?_ . "w"))))
    )

(provide 'rewrite-mode)

;;;; End of rewrite-mode.el
    
