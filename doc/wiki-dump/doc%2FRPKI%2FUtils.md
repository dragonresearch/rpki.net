# RPKI utility programs

The distribution contains a few small utility programs. Most of these are
nominally relying party tools, but work at a low enough level that they may
also be useful in diagnosing CA problems.

Unless otherwise specified, all of these tools expect RPKI objects
(certificates, CRLs, CMS signed objects) to be in DER format.

Several of these tools accept an `rcynic_directory` argument. Which directory
to specify here depends on what you're trying to do, but if you're just trying
to look at authenticated data in your RP cache, and assuming you've installed
everything in the default locations, the directory you want is probably
`/var/rcynic/data/authenticated`.

## uri

`uri` is a utility program to extract URIs from the SIA, AIA, and CRLDP
extensions of one or more X.509v3 certificates, either specified directly or
as CMS objects containing X.509v3 certificates within the CMS wrapper.

Usage:

    
    
    $ uri [-h | --help] [-s | --single-line] cert [cert...]
    

`-h --help`

     Show help 
`-s --single-line`

     Single output line per input file 
`cert`

     Object(s) to examine 

## hashdir

`hashdir` copies an authenticated result tree from an rcynic run into the
format expected by most OpenSSL-based programs: a collection of "PEM" format
files with names in the form that OpenSSL's `-CApath` lookup routines expect.
This can be useful for validating RPKI objects which are not distributed as
part of the repository system.

Usage:

    
    
    $ hashdir [-h | --help] [-v | --verbose] rcynic_directory output_directory
    

`-h --help`

     Show help 
`-v --verbose`

     Whistle while you work 
`rcynic_directory`

     rcynic authenticated output tree 
`output_directory`

     Output directory to create 

## print_rpki_manifest

`print_rpki_manifest` pretty-prints the content of a manifest. It does _NOT_
attempt to verify the signature.

Usage:

    
    
    $ print_rpki_manifest [-h | --help] [-c | --cms] manifest [manifest...]
    

`-h --help`

     Show help 
`-c --cms`

     Print text representation of entire CMS blob 
`manifest`

     Manifest(s) to print 

## print_roa

`print_roa` pretty-prints the content of a ROA. It does _NOT_ attempt to
verify the signature.

Usage:

    
    
    $ print_roa [-h | --help] [-b | --brief] [-c | --cms] [-s | --signing-time] ROA [ROA...]
    

`-h --help`

     Show help 
`-b --brief`

     Brief mode (only show ASN and prefix) 
`-c --cms`

     Print text representation of entire CMS blob 
`-s --signing-time`

     Show CMS signingTime 
`ROA`

     ROA object(s) to print 

## find_roa

`find_roa` searches the authenticated result tree from an rcynic run for ROAs
matching specified prefixes.

Usage:

    
    
    $ find_roa [-h | --help] [-a | --all]
               [-m | --match-maxlength ] [-f | --show-filenames]
               [-i | --show-inception]   [-e | --show-expiration]
               authtree [prefix...]
    

`-h --help`

     Show help 
`-a --all`

     Show all ROAs, do no prefix matching at all 
`-e --show-expiration`

     Show ROA chain expiration dates 
`-f --show-filenames`

     Show filenames instead of URIs 
`-i --show-inception`

     Show inception dates 
`-m -match-maxlength`

     Pay attention to maxLength values 
`authtree`

     rcynic authenticated output tree 
`prefix`

     ROA prefix(es) to on which to match 

## scan_roas

`scan_roas` searchs the authenticated result tree from an rcynic run for ROAs,
and prints out the signing time, ASN, and prefixes for each ROA, one ROA per
line.

Other programs such as the [rpki-rtr client][1] use `scan_roas` to extract the
validated ROA payload after an rcynic validation run.

Usage:

    
    
    $ scan_roas [-h | --help] rcynic_directory [rcynic_directory...]
    

`-h --help`

     Show help 
`rcynic_directory`

     rcynic authenticated output tree 

## scan_routercerts

`scan_routercerts` searchs the authenticated result tree from an rcynic run
for BGPSEC router certificates, and prints out data of interest to the rpki-
rtr code.

Other programs such as the [rpki-rtr client][1] use `scan_routercerts` to
extract the validated ROA payload after an rcynic validation run.

Usage:

    
    
    $ scan_routercerts [-h | --help] rcynic_directory [rcynic_directory...]
    

`-h --help`

     Show help 
`rcynic_directory`

     rcynic authenticated output tree 

   [1]: #_.wiki.doc.RPKI.RP.rpki-rtr

