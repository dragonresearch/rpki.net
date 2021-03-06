# [web_portal] section

Glue to allow the Django application to pull user configuration from this file
rather than directly editing settings.py.

## sql-database

SQL database name the web portal should use.

    
    
    sql-database = ${myrpki::irdbd_sql_database}
    

## sql-username

SQL user name the web portal should use.

    
    
    sql-username = ${myrpki::irdbd_sql_username}
    

## sql-password

SQL password the web portal should use.

    
    
    sql-password = ${myrpki::irdbd_sql_password}
    

## secret-key

Site-specific secret key for Django.

No default value.

## allowed-hosts

Name of virtual host that runs the Django GUI, if this is not the same as the
system hostname. Django's security code wants to know the name of the virtual
host on which Django is running, and will fail when it thinks it's running on
a disallowed host.

If you get an error like "Invalid HTTP_HOST header (you may need to set
ALLOWED_HOSTS)", you will need to set this option.

No default value.

## download-directory

A directory large enough to hold the RouteViews?.org routing table dump
fetched by the rpkigui-import-routes script.

    
    
    download-directory = /var/tmp
    

