;;; $Id$
;;;
;;; Scratch pad for working out API design for registration engine.
;;;
;;; This file is psuedocode, I just wanted to take advantage of
;;; emacs's built-in support for languages with reasonable syntax.



;;; Protocol operations between registration engine and signing engine.
;;; This assumes the model in which the signing engine stores nothing
;;; but keypairs and takes orders from the registration engine on what
;;; to sign; this still needs to be checked by competent paranoids.

;; Create a keypair.  :length is the number of bits for the key
;; (default 2048?).  :handle is optional, and is here to allow forward
;; references within a sneakernet queue.

(create-keypair :cust-id 42
		:length 2048
		:handle customer-42s-new-keypair)
=> (public-key handle)

;; Destroy a keypair.

(destroy-keypair :cust-id 42
		 :public-key public-key)
=> ()

;; List existing keypairs

(list-keypairs :cust-id 42)
=> (public-key public-key ...)

;; Sign something.  Will probably need to break this down into
;; separate signing calls for each kind of thing to be signed, but
;; most likely they will all look pretty much alike.  One of
;; :key-to-use or :key-handle must be specified.

(sign-thing :cust-id		42
	    :what-to-sign	blob
	    :how-to-sign	:rsa/sha256
	    :key-to-use		public-key
	    :key-handle		handle-for-public-key)
=> (signed-thing)

;; Do we need a verify operation here that can take a handle so we can
;; verify things that were signed by keys that don't exist yet at the
;; time we're queuing up the sneakernet channel?  Hope not, sounds
;; complicated.  Punt for now.



;;; Protocol operations between IR back-end and registration engine.
;;;
;;; At the moment this is not even 1/4 baked, it's just a list of
;;; functions to be filled in with arguments and results, and some of
;;; these may not really need to cross the IR back-end / registration
;;; engine boundary at all.  To be refined....

(create-cust-id)
=> (customer-id)

(destroy-cust-id :cust-id 42)
=> ()

(list-cust-ids)
=> (customer-id ...)

(get-preference :cust-id 42
		:preference-name :favorite-color)
=> ("obsidian")

(set-preference :cust-id 42
		:name  :favorite-color
		:value "obsidian")
=> ()

(add-resource :cust-id 42
	      :name  :ipv4-address
	      :value "10.0.0.44/32")
=> ()

(del-resource :cust-id 42
	      :name  :ipv4-address
	      :value "10.0.0.44/32")
=> ()

(list-resources :cust-id 42)
=> ((:ipv4-address . "10.0.0.44/32") ...)

(get-biz-private-key :cust-id 42)
=> (private-key)

(set-biz-private-key :cust-id 42
		     :new-key new-private-key)
=> ()

(add-friend-biz-cert :cust-id 42
		     :cert cert)
=> ()

(del-friend-biz-cert :cust-id 42
		     :cert cert)
=> ()

(list-friend-biz-certs :cust-id 42)
=> (cert ...)

;;; Stuff below this line is not even close to baked yet

;; These two may take a bit more thought.  What's a ca-handle?

(create-ca-context :cust-id 42
		   :distinguished-name dn)
=> (ca-handle)

(destroy-ca-context :cust-id 42
		    :ca-handle handle)
=> ()

;; Ask signing engine to generate a cert request with specified
;; attributes and indicated (subject) keyset.  Key handle is in case
;; we have to ask signing engine to create a keypair for this.

(generate-cert-request :cust-id 42
		       :subject-name subject-name
		       :attributes '(blah blah blah)
		       :public-key public-key
		       :public-key-handle handle)

;; Ask signing engine to sign a CRL.  Need to indicate the CA that's
;; generating the CRL

(generate-crl :cust-id 42
	      :ca-handle ca-handle)

;; Ask signing engine to sign a cert request using specified cert
;; request and attributes and indicated (issuer) keyset.

(sign-cert-request)

(add-right-to-route)
(del-right-to-route)
(list-rights-to-route)

(generate-roa)

(publish-cert)
(publish-crl)
(publish-roa)

;; Trigger poll of this cust id's external parent, no-op if parent is
;; not external.  What does reg engine do with responses, save them as
;; part of its internal state then go back to sleep?

(poll-external-parent)

;; Trigger this cust id to do its "nightly" cycle.  Most likely needs
;; to be broken down further.

(run-nightly-batch)
