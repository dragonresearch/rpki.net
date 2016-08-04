# APRICOT 2013 RPKI CA Hackathon, Signapore

## Options For Installation

  * FreeBSD binary packages (currently only FreeBSD 8-STABLE 
    * <http://download.rpki.net/FreeBSD_Packages/rpki-rp-0.5080.tbz>
    * <http://download.rpki.net/FreeBSD_Packages/rpki-ca-0.5080.tbz>
  * FreeBSD ports (any recent FreeBSD version) 
    * <http://download.rpki.net/FreeBSD_Packages/rpki-rp-port.tgz>
    * <http://download.rpki.net/FreeBSD_Packages/rpki-ca-port.tgz>
  * Ubuntu 12.04LTS binary packages 
    * <http://download.rpki.net/Ubuntu_Packages/rpki-ca_0.5080_i386.deb>
    * <http://download.rpki.net/Ubuntu_Packages/rpki-rp_0.5080_i386.deb>
  * [Build from source without package support][1]
  * JPNIC has VirtualBox images 
  * JPNIC has virtual machines 

## FreeBSD binary packages on FreeBSD 8-STABLE

    
    
    fetch http://download.rpki.net/FreeBSD_Packages/rpki-rp-0.5080.tbz
    fetch http://download.rpki.net/FreeBSD_Packages/rpki-ca-0.5080.tbz
    pkg_add rpki-*.tbz
    

## FreeBSD ports

    
    
    fetch -o - http://download.rpki.net/FreeBSD_Packages/rpki-rp-port.tgz | tar xf -
    cd rpki-rp
    make install
    cd ..
    fetch -o - http://download.rpki.net/FreeBSD_Packages/rpki-ca-port.tgz | tar xf -
    cd rpki-ca
    make install
    cd ..
    

## FreeBSD ports with portmaster packages

    
    
    mkdir /usr/ports/local
    cd /usr/ports/local
    fetch -o - http://download.rpki.net/FreeBSD_Packages/rpki-rp-port.tgz | tar xf -
    fetch -o - http://download.rpki.net/FreeBSD_Packages/rpki-ca-port.tgz | tar xf -
    portmaster -Pv local/rpki-rp local/rpki-ca
    

## Ubuntu 12.04LTS packages

    
    
    wget http://download.rpki.net/Ubuntu_Packages/rpki-ca_0.5080_i386.deb
    wget http://download.rpki.net/Ubuntu_Packages/rpki-rp_0.5080_i386.deb
    dpkg -i rpki-*.deb
    

## Configuring the CA software

  * Copy rpki.conf.sample to rpki.conf 
  * Edit as needed (see comments in file and see [the documentation][2]). 
  * FreeBSD: `emacs /usr/local/etc/rpki.conf.sample`
  * Ubuntu: `emacs /etc/rpki.conf.sample`

## Initializing the CA software

    
    
    rpki-sql-setup
    rpkic initialize
    

## Start the daemons: FreeBSD

  * Add `rpkica_enable="YES"` to /etc/rc.conf 
  * Add `inetd_enable="YES"` to /etc/rc.conf 
    
    
    service inetd restart
    service rpki-ca start
    

## Start the daemons: Ubuntu

    
    
    sudo initctl start rpki-ca
    

## Dance With Your Parent

See: [Command line interface documentation][3]

  * Child sends XML to parent 
  * Parent runs rpkic configure_child 
  * Parent sends result to child 
  * Child runs rpkic configure_parent 
  * Child sends repository request to repository (parent or self, depending on child's configuration) 
  * Repository runs configure_publication_client 
  * Repository sends result to child 
  * Child runs configure_repository 

## Set Up The GUI

See: [Graphical web interface documentation][4]

   [1]: #_.wiki.doc.RPKI

   [2]: #_.wiki.doc.RPKI.CA.Configuration

   [3]: #_.wiki.doc.RPKI.CA.UI

   [4]: #_.wiki.doc.RPKI.CA.UI.GUI

