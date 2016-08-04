# Upgrading From Sqlite to MySQL Backend

If you originally deployed the Web Portal using the sqlite backend, you can
migrate to the MySQL backend using the steps detailed on this page.

## Bring source tree up to date

If you have not already done so, bring your copy of the subversion repository
up to date:

    
    
    # cd $top
    # svn up
    

Where _${top}_ is the top level directory of the SVN repository.

## Backup Current Sqlite Database

Create a backup of the database. The dump will only contain the data from the
`rpki.gui.app` and `django.contrib.auth`, which are the only Django
applications that contain site-specific data.

    
    
    # ${top}/rpkid/portal-gui/scripts/dumpdata.py > gui-backup.json
    

Where _${top}_ is the top level directory of the SVN repository.

**Note**: On some systems such as FreeBSD, the command is `django-admin.py` (with the `.py` suffix). 

## Backup Current IRDB

After this upgrade, the Web Portal will store its SQL tables in the same MySQL
database used by `irdbd`. Therefore, it is a good idea to create a backup of
your current IRDB prior to performing the upgrade. By default, the database is
named _irdbd_. Consult your `rpki.conf` and look in the _myrpki_ section
(default is the first section of the file) for the line that looks like this:

    
    
    irdbd_sql_database              = irdbd
    

Once you have determined the correct database, you can create the backup:

    
    
    # mysqldump -u root -p irdbd > irdb-backup.sql
    

Replace _irdbd_ with the name of your database from your `rpki.conf` if you
customized it.

## Install Software

At this point you should install the software if you have not already done so:

    
    
    # cd ${top}
    # make clean
    # ./configure
    # make
    # make install
    

## Editing rpki.conf

Edit your `rpki.conf` and add the following section at the end of the file:

    
    
    [web_portal]
    sql-database = ${myrpki::irdbd_sql_database}
    sql-user     = ${myrpki::irdbd_sql_username}
    sql-password = ${myrpki::irdbd_sql_password}
    

## Creating /usr/local/etc/rpki.conf

The web portal now expects that the `rpki.conf` for the self-hosted resource
handle (i.e. the `rpki.conf` with **run_rpkid = True**) is accessible via the
system configuration directory. This is typically `/usr/local/etc/rpki.conf`.
If you have been running the rpki tools with the rpki.conf in
`/usr/local/var/rpki/conf/${HANDLE}/rpki.conf` you have one of two choices:

  1. Move the `rpki.conf` to `/usr/local/etc/`
  2. Create a symbolic link from your `rpki.conf` to `/usr/local/etc/rpki.conf`

## Create Database Tables

This steps creates the database tables used by the Web Portal.

    
    
    # django-admin syncdb --settings=settings --pythonpath=/usr/local/etc/rpki --noinput
    

The **\--noinput** argument is specified to suppress the prompt to create a
superuser account. It is assumed that you had orignally created a superuser
account in the sqlite backend which will be recreated when you restore the
database dump as the final step in the migration process.

## Restore Data from Backup

The final step is to restore the data from the backup created in the first
step.

    
    
    # django-admin loaddata --settings=settings --pythonpath=/usr/local/etc/rpki gui-backup.json
    

## Restart the Web Server

The final step is to restart the web server so that the web portal is served
up using the new mysql backend.

