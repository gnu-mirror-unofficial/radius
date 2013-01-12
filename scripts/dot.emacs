;;; -*- emacs-lisp -*-
;;
;; Copyright (C) 2002, 2013 Free Software Foundation
;; This file is free software; as a special exception the author gives
;; unlimited permission to copy and/or distribute it, with or without
;; modifications, as long as this notice is preserved.
;;
;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
;; implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

;; po-specific interface to ispell- functions
(defun po-ispell-run (fun &rest args)
  (if (eq major-mode 'po-mode)
      (if (po-check-all-pending-edits)
	  (let* ((save-ispell-skip-region-alist ispell-skip-region-alist)
		 (ispell-skip-region-alist (append
					    '(("#.*")
					      ("msgid" . "msgstr"))
					    save-ispell-skip-region-alist)))
	    (setq buffer-read-only po-read-only)
	    (fundamental-mode)
	    (apply fun args)
	    (po-mode)))))

(defun po-ispell-buffer ()
  "Check current PO file for spelling errors in translation strings."
  (interactive)
  (po-ispell-run 'ispell-buffer))
  
(defun po-ispell-region (reg-start reg-end)
  "Check a region of the current PO file for spelling errors in
translation strings."
  (interactive "r")  
  (po-ispell-run 'ispell-region reg-start reg-end))

(defun rad-po-mode-hook ()
  (define-key po-mode-map "i" 'po-ispell-buffer)
  (define-key po-mode-map "\M-i" 'po-ispell-region))

(defun rad-po-subedit-mode-hook ()
  (let ((method (assoc 'default-input-method (buffer-local-variables buffer))))
    (if method
	(set-input-method (cdr method)))))

(require 'po-mode)
(add-hook 'po-mode-hook 'rad-po-mode-hook)
(add-hook 'po-subedit-mode-hook 'rad-po-subedit-mode-hook)
