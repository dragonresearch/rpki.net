<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY dbstyle SYSTEM "/usr/share/sgml/docbook/dsssl-stylesheets-1.77/print/docbook.dsl" CDATA DSSSL>
]>

<style-sheet>
<style-specification use="docbook">
<style-specification-body>

;; user modifications
(define %paper-type% "A4")
(define %default-quadding% 'justify)
(define %block-sep% (* %para-sep% 1.0))


;; modify paramdef to replace trailing semicolon with colon
(element paramdef
  (let ((param (select-elements (children (current-node)) (normalize "parameter"))))
    (make sequence
      (if (equal? (child-number (current-node)) 1)
	  (literal "(")
	  (empty-sosofo))
      (if (equal? %funcsynopsis-style% 'ansi)
	  (process-children)
	  (process-node-list param))
      (if (equal? (gi (ifollow (current-node))) (normalize "paramdef"))
	  (literal ", ")
	  (literal "):")))))

(element void
  (literal "():"))

(element parameter ($mono-seq$))

(mode cs-python-mode
  (element classsynopsis
    (let* ((classes      (select-elements (children (current-node))
					  (normalize "ooclass")))
	   (classname    (node-list-first classes))
	   (superclasses (node-list-rest classes)))
      (make display-group
	use: verbatim-style
	(make paragraph
	  (literal "class ")
	  (process-node-list classname)
     (if (node-list-empty? superclasses)
        (literal ":")
        (make sequence
           (literal "(")
           (process-node-list superclasses)
           (literal "):"))))
	(process-node-list
	 (node-list-filter-by-gi
	  (children (current-node))
	  (list (normalize "constructorsynopsis")
		(normalize "destructorsynopsis")
		(normalize "fieldsynopsis")
		(normalize "methodsynopsis")
		(normalize "classsynopsisinfo"))))
	))))

(element ooclass
  (make sequence
    (process-children)
      (cond
        ;;((first-sibling?) (literal " "))
        ((first-sibling?) (empty-sosofo))
        ((last-sibling?) (empty-sosofo))
        (#t (literal ", ")))))


  (element constructorsynopsis
    (python-constructor-synopsis))

  (element destructorsynopsis
    (python-constructor-synopsis))

  (element classsynopsisinfo
     ($verbatim-display$ %indent-classsynopsisinfo-lines% %number-classsynopsisinfo-lines%))

(define (python-constructor-synopsis #!optional (nd (current-node)))
   (let* ((the-method-params (select-elements (children nd) (normalize "methodparam"))))
   (make paragraph
      (literal "    def __init__(")
      (process-node-list the-method-params)
      (literal "):"))))

(define (python-destructor-synopsis #!optional (nd (current-node)))
   (let* ((the-method-params (select-elements (children nd) (normalize "methodparam"))))
   (make paragraph
      (literal "    def __del__(")
      (process-node-list the-method-params)
      (literal "):"))))

;;(element parameter
;;   (process-children))

(define (python-method-synopsis #!optional (nd (current-node)))
  (let* ((the-method-name (select-elements (children nd) (normalize "methodname")))
	 (the-method-params (select-elements (children nd) (normalize "methodparam")))
	 )
    (make paragraph
      (literal "    def ")
      (process-node-list the-method-name)
      (literal "(")
      (process-node-list the-method-params)
      (literal "):"))))


</style-specification-body>
</style-specification>
<external-specification id="docbook" document="dbstyle">
</style-sheet>
