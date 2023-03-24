---
title: "How to install Nextcloud 25 on FreeBSD"
date: 2023-03-24
---

# WORK IN PROGRESS !!!

---

I'm currently learning how to install Nextcloud on FreeBSD from sratch and would like to share what I've got so far.

**Disclaimer**

- I am still learning, errors will be made, so please don't blindly follow this guide.
- This is a work in progress, so feel free to point out things that can be improved.
- Running Nextcloud on FreeBSD with Nginx is not officially supported, but works™.

---

**Components that need to be installed**

- PostgreSQL 13.9
- Nginx 1.22
- PHP 8.1
- Redis 7.0 (optional)

---

# Host

- Install FreeBSD, preferably the latest RELEASE
- Set a static IP Address
- Install the latest patches with `freebsd-update fetch install`
- Install your favorite text editor (I'll use vim, feel free to use anything you like)
- Install sudo(8) or doas(8) for privilige escalation and setting up cronjobs for other users 

---

# PKG

**Set pkg up to use latest instead of quarterly packages**

```shell
sudo mkdir -p /usr/local/etc/pkg/repos
```

```shell
sudo vim /usr/local/etc/pkg/repos/FreeBSD.conf
```

```vim
FreeBSD: {
	url: "pkg+http://pkg.FreeBSD.org/${ABI}/latest"
}
```

```shell
sudo pkg update && sudo pkg upgrade -y 
```

---

# Cronjobs

**Set up a cronjob for Nextcloud house keeping:**

```shell
sudo -u www crontab -e
```

(press "i" to insert, then paste, then press [Esc] ":wq" and hit Return)

```vim
*/5     *       *       *       *       /usr/local/bin/php /usr/local/www/nextcloud/cron.php
```

**Set up a cronjob so sendmail eat up all disk space:**

```shell
sudo vim /etc/cron.d/sendmail-clean-clientmqueue
```

```vim
0     *       *       *       *       root /bin/rm -r -f /var/spool/clientmqueue/*
```

---

# Database

**As PostgreSQL files are mostly 8 KB in size, we will create a seperate dataset for it:**

Info: Setting a record size smaller than 128 KB will lead to fragmentation.

(The "base" Dataset will be created with the "canmount=off" flag, so the FreeBSD ZFS boot environments are happy) 

I suppose your ZFS dataset is called "zroot", if it differs, change it in the commands:

```shell
sudo zfs create -o canmount=off zroot/var/db
```

**Create a dataset for postgres configuration files:**

```shell
sudo zfs create zroot/var/db/postgres
```

**Create the dataset for postgres database files and set the record size to 8K:**

```shell
sudo zfs create zroot/var/db/postgres/data13
```

```shell
sudo zfs set recordsize=8K zroot/var/db/postgres/data13
```

**Install the PostgreSQL package, as we will need the user and group created by pkg:**

```shell
sudo pkg install postgresql13-server postgresql13-client
```

**Give postgres full ownership of it's dataset:**

```shell
sudo chown postgres:postgres /var/db/postgres/data13
```

**Enable, Initialyse and start the postgres database:**

(this step will fail if /var/db/postgres/data13 is still owned by root / wheel):

```shell
sudo service postgresql enable
```

```shell
sudo service postgresql initdb
```

```shell
sudo service postgresql start
```

**Create the postgres database and role for nextcloud:**

(Tip: use a stronger database password):

```shell
sudo psql -hlocalhost -Upostgres
```

```sql
CREATE DATABASE nextcloud;
#CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
```

```sql
CREATE USER nextcloud WITH PASSWORD 'NEXTCLOUD_DB_PASSWORD';
#CREATE USER nextcloud WITH ENCRYPTED PASSWORD 'NEXTCLOUD_DB_PASSWORD';
```

```sql
GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
#ALTER DATABASE nextcloud OWNER TO nextcloud;
```

```sql
\q
```

**Set up a cronjob for PostgreSQL house keeping (credits to Vermaden):**

```shell
sudo mkdir /var/db/postgres/bin
```

```shell
sudo vim /var/db/postgres/bin/vacuum.sh
```

`:set paste`

```vim
#! /bin/sh
/usr/local/bin/vacuumdb -az 1> /dev/null 2> /dev/null
/usr/local/bin/reindexdb -a 1> /dev/null 2> /dev/null
/usr/local/bin/reindexdb -s 1> /dev/null 2> /dev/null
```

```shell
sudo -u postgres crontab -e
```

```vim
0       0       *       *       *       /var/db/postgres/bin/vacuum.sh
```

---

# Webserver


**Install the Nginx package:**

```shell
sudo pkg install nginx
```

**Enable Nginx:**

```shell
sudo service nginx enable
```

**Create the Nextcloud directories:**

```shell
sudo mkdir -p /usr/local/www/nextcloud/data
```

**If you'de like, you can mount a NFS share or ZFS pool in /data:**

```shell
sudo vim /etc/fstab
```

```vim
172.31.20.10:/mnt/pool1/ds1/services/nextcloud-test /usr/local/www/nextcloud/data nfs rw 0 0
```

```shell
sudo mount -a
```

**Give the nginx user full ownership of the nextcloud directory:**

```shell
#sudo chown -R www:www /usr/local/www/nextcloud
```

**Insert the Nginx configuration**

(I copied and modified the nginx configuration from Nexcloud's Adnmin guide and put in some lines from my TrueNAS CORE Nextcloud jail):

```shell
sudo mv /usr/local/etc/nginx/nginx.conf /usr/local/etc/nginx/nginx.conf.orig
```

```shell
sudo vim /usr/local/etc/nginx/nginx.conf
```

Info: Make shure to change `nextcloud.example.com` to a hostname that resolves to the IP-address of your server, or you won't be able to access Nextcloud!
Alternatively, change `nextcloud.example.com` in both lines containing (in the server section) `server_name nextcloud.example.com;` to the IP-Address of your server and restart the nginx service.

**Timeout (504 Gateway Time-Out)**

Info: On slow system, add this to `nginx.conf` to prevent a 504 timeout after 60 seconds after completing the Nextcloud installation.

```
fastcgi_read_timeout 300;
```
Example: `server_name 172.31.20.14;`

`:set paste`

```vim

user  www;
worker_processes auto;

# This default error log path is compiled-in to make sure configuration parsing
# errors are logged somewhere, especially during unattended boot when stderr
# isn't normally logged anywhere. This path will be touched on every nginx
# start regardless of error log location configured here. See
# https://trac.nginx.org/nginx/ticket/147 for more info. 
#
pid        /var/run/nginx.pid;


events {
    use kqueue;
    worker_connections  1024;
    multi_accept on;
}


http {

    # Logging
    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log;

    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    reset_timedout_connection on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    send_timeout 30;
    server_names_hash_max_size 4096;

    # Common limits
    client_header_timeout 180s;
    client_body_temp_path /var/tmp/nginx/client_body_temp;
    #proxy_connect_timeout 5;
    #proxy_send_timeout 10;
    #proxy_read_timeout 10;
    proxy_buffer_size 4k;
    proxy_buffers 8 16k;
    proxy_busy_buffers_size 64k;
    proxy_temp_file_write_size 64k;
    proxy_temp_path /var/tmp/nginx/proxy_temp;
    include mime.types;
    default_type application/octet-stream;

    # Cache config
    proxy_cache_valid 1m;


    # Set the `immutable` cache control options only for assets with a cache busting `v` argument
    map $arg_v $asset_immutable {
        "" "";
        default "immutable";
    }
    
    upstream php-handler {
        #server 127.0.0.1:9000;
        server unix:/var/run/php-fpm.sock;
    }
    
    server {
        listen 80;
        listen [::]:80;
        server_name nextcloud.example.com;
    
        # Prevent nginx HTTP Server Detection
        server_tokens off;
    
        # Enforce HTTPS
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443      ssl http2;
        listen [::]:443 ssl http2;
        server_name nextcloud.example.com;
    
        # Path to the root of your installation
        root /usr/local/www/nextcloud;
    
        # Use Mozilla's guidelines for SSL/TLS settings
        # https://mozilla.github.io/server-side-tls/ssl-config-generator/
        ssl_certificate     /usr/local/etc/nginx/ssl/server.crt;
        ssl_certificate_key /usr/local/etc/nginx/ssl/server.key;
    
        # Prevent nginx HTTP Server Detection
        server_tokens off;
    
        # HSTS settings
        # WARNING: Only add the preload option once you read about
        # the consequences in https://hstspreload.org/. This option
        # will add the domain to a hardcoded list that is shipped
        # in all major browsers and getting removed from this list
        # could take several months.
        add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;
    
        # set max upload size and increase upload timeout:
        client_max_body_size 10G;
        client_body_timeout 300s;
        fastcgi_buffers 64 4K;
    
        # Enable gzip but do not remove ETag headers
        gzip on;
        gzip_vary on;
        gzip_comp_level 4;
        gzip_min_length 256;
        gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
        gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/wasm application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;
    
        # Pagespeed is not supported by Nextcloud, so if your server is built
        # with the `ngx_pagespeed` module, uncomment this line to disable it.
        #pagespeed off;
    
        # The settings allows you to optimize the HTTP2 bandwitdth.
        # See https://blog.cloudflare.com/delivering-http-2-upload-speed-improvements/
        # for tunning hints
        client_body_buffer_size 512k;
    
        # HTTP response headers borrowed from Nextcloud `.htaccess`
        add_header Referrer-Policy                   "no-referrer"       always;
        add_header X-Content-Type-Options            "nosniff"           always;
        add_header X-Download-Options                "noopen"            always;
        add_header X-Frame-Options                   "SAMEORIGIN"        always;
        add_header X-Permitted-Cross-Domain-Policies "none"              always;
        add_header X-Robots-Tag                      "none" always;
        add_header X-XSS-Protection                  "1; mode=block"     always;
    
        # Remove X-Powered-By, which is an information leak
        fastcgi_hide_header X-Powered-By;
    
        # Specify how to handle directories -- specifying `/index.php$request_uri`
        # here as the fallback means that Nginx always exhibits the desired behaviour
        # when a client requests a path that corresponds to a directory that exists
        # on the server. In particular, if that directory contains an index.php file,
        # that file is correctly served; if it doesn't, then the request is passed to
        # the front-end controller. This consistent behaviour means that we don't need
        # to specify custom rules for certain paths (e.g. images and other assets,
        # `/updater`, `/ocm-provider`, `/ocs-provider`), and thus
        # `try_files $uri $uri/ /index.php$request_uri`
        # always provides the desired behaviour.
        index index.php index.html /index.php$request_uri;
    
        # Rule borrowed from `.htaccess` to handle Microsoft DAV clients
        location = / {
            if ( $http_user_agent ~ ^DavClnt ) {
                return 302 /remote.php/webdav/$is_args$args;
            }
        }
    
        location = /robots.txt {
            allow all;
            log_not_found off;
            access_log off;
        }
    
        # Make a regex exception for `/.well-known` so that clients can still
        # access it despite the existence of the regex rule
        # `location ~ /(\.|autotest|...)` which would otherwise handle requests
        # for `/.well-known`.
        location ^~ /.well-known {
            # The rules in this block are an adaptation of the rules
            # in `.htaccess` that concern `/.well-known`.
    
            location = /.well-known/carddav { return 301 /remote.php/dav/; }
            location = /.well-known/caldav  { return 301 /remote.php/dav/; }
    
            location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }
            location /.well-known/pki-validation    { try_files $uri $uri/ =404; }
    
            # Let Nextcloud's API for `/.well-known` URIs handle all other
            # requests by passing them to the front-end controller.
            return 301 /index.php$request_uri;
        }
    
        # Rules borrowed from `.htaccess` to hide certain paths from clients
        location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
        location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)                { return 404; }
    
        # Ensure this block, which passes PHP files to the PHP process, is above the blocks
        # which handle static assets (as seen below). If this block is not declared first,
        # then Nginx will encounter an infinite rewriting loop when it prepends `/index.php`
        # to the URI, resulting in a HTTP 500 error response.
        location ~ \.php(?:$|/) {
            # Required for legacy support
            rewrite ^/(?!index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|oc[ms]-provider\/.+|.+\/richdocumentscode\/proxy) /index.php$request_uri;
    
            fastcgi_split_path_info ^(.+?\.php)(/.*)$;
            set $path_info $fastcgi_path_info;
    
            try_files $fastcgi_script_name =404;
    
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $path_info;
            fastcgi_param HTTPS on;
    
            fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
            fastcgi_param front_controller_active true;     # Enable pretty urls
            fastcgi_pass php-handler;
    
            fastcgi_intercept_errors on;
            fastcgi_request_buffering off;
    
            fastcgi_max_temp_file_size 0;
        }
    
        location ~ \.(?:css|js|svg|gif|png|jpg|ico|wasm|tflite|map)$ {
            try_files $uri /index.php$request_uri;
            add_header Cache-Control "public, max-age=15778463, $asset_immutable";
            access_log off;     # Optional: Don't log access to assets
    
            location ~ \.wasm$ {
                default_type application/wasm;
            }
        }
    
        location ~ \.woff2?$ {
            try_files $uri /index.php$request_uri;
            expires 7d;         # Cache-Control policy borrowed from `.htaccess`
            access_log off;     # Optional: Don't log access to assets
        }
    
        # Rule borrowed from `.htaccess`
        location /remote {
            return 301 /remote.php$request_uri;
        }
    
        location / {
            try_files $uri $uri/ /index.php$request_uri;
        }
    }
}
```


---

# OpenSSL

**Now we will generate a TLS certificate with the help of OpenSSL:**

Alternatively, you can use a certificate from Let’s Encrypt.

**Create the directory where the certificates will be stored:**

```shell
sudo mkdir -p /usr/local/etc/nginx/ssl
```

**Create the TLS private key:**

```shell
cd /usr/local/etc/nginx/ssl
```

```shell
sudo openssl genrsa -out server.key 2048
```

**Create a TLS certificate singing request:**

```shell
sudo openssl req -new -key server.key -out server.csr
```
```shell
- Country Name (2 letter code) [AU]: Two letter country code
- State or Province Name (full name) [Some-State]: state name
- Locality Name (eg, city) []: city name
- Organization Name (eg, company) [Internet Widgits Pty Ltd]: Company name or last name
- Organizational Unit Name (eg, section) []: e.g. Homelab
- Common Name (e.g. server FQDN or YOUR name) []: reverse dns name of IP-address
- Email Address []: hostmaster@example.net
- A challenge password []: ********
- An optional company name []: no idea
```

**Create the TLS certificate:**

```shell
sudo openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

```shell
cd
```


---

# PHP

**Now we can install PHP and all of the extentions we will need:**

**Install PHP and it's extentions:**

(This may take a wile depending on your Internet connection and the speed of your system.)

```shell
sudo pkg install php81 php81-bcmath php81-bz2 php81-ctype php81-curl php81-dom php81-exif php81-fileinfo php81-filter php81-gd php81-gmp php81-iconv php81-intl php81-ldap php81-mbstring php81-opcache php81-pcntl php81-pdo_mysql php81-pdo_pgsql php81-pecl-APCu php81-pecl-imagick php81-pgsql php81-posix php81-session php81-simplexml php81-xml php81-xmlreader php81-xmlwriter php81-xsl php81-zip php81-zlib 
```

**Activate and start the php-fpm deamon:**

```shell
sudo service php-fpm enable
```

**Create the PHP configuration file by copying the production default file:**

```shell
sudo cp /usr/local/etc/php.ini-production /usr/local/etc/php.ini
```

**Modify the PHP configuration:**

```shell
sudo vim /usr/local/etc/php.ini
```

(search for keywords with Esc + /)

```vim
memory_limit = 1G (or 512M if you have limited RAM)
upload_max_filesize = 10G
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.revalidate_freq=1
opcache.save_comments=1
```

**Add this to the end of the Configuration file if you want to use Redis for caching:**

```vim
;;;;;;;;;
; Redis ;
;;;;;;;;;
; Prevent Nextcloud session corruption when redis cache is used
redis.session.locking_enabled = 1
redis.session.lock_retries = -1
redis.session.lock_wait_time = 10000
```

**Edit php-fmp.conf:**

```shell
sudo vim /usr/local/etc/php-fpm.d/www.conf
```

**Change the following line:**

```vim
listen = 127.0.0.1:9000 -> listen = /var/run/php-fpm.sock
```

**Uncomment the following lines:**

```vim
listen.owner = www
listen.group = www
listen.mode = 0660
...
env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
```

---

# Nextcloud

**Download Nextcloud:**

```shell
cd /usr/local/www/
```

```shell
sudo fetch https://download.nextcloud.com/server/releases/latest.zip
```

**Extact Nextcloud:**

```shell
sudo unzip latest.zip
```

**Change the permission of the extracted Nextcloud files to www (Nginx):**

```shell
sudo chown -R www:www /usr/local/www/nextcloud/
```

**Remove the latest.zip file (if no longer needed):**

```shell
sudo rm latest.zip
```

**Start all the Services:**

```shell
sudo service php-fpm start
```

```shell
sudo service nginx start
```


---

# Setup

Set up Nextcloud with your Webbrowser of choice:**

**Access the IP-Address of your Nextcloud Server to start the Setup process**

```
- Username: ncadmin (or chose another admin name)
- Password: ******** (chose something really, REALLY stong)
- Database setup: PostgreSQL
- Database user: nextcloud
- Database password: NEXTCLOUD_DB_PASSWORD (use your own secure database password here)
- Database-Name: nextcloud
- Database-Host: localhost
- Install
```

---

# Redis (Optional)

**Install Redis for caching and session handling:**

```shell
sudo pkg install redis php81-pecl-redis
```

**Enable Redis:**

```shell
sudo service redis enable
```

**Edit the Redis configuration file:**

```shell
sudo vim /usr/local/etc/redis.conf
```

**Change the following line:**

(Unix sockets are a lot faster than TCP sockets)

```vim
port 6379 -> port 0
```

**Uncomment and edit the following lines:**

```vim
#unixsocket /run/redis.sock -> unixsocket /var/run/redis/redis.sock
#unixsocketperm 700 -> unixsocketperm 770
```

**Add Nginx to the Redis group (like php-fpm):**

```shell
sudo pw groupmod redis -m www
```

**Activate Redis Caching in Nextcloud:**

```shell
sudo vim /usr/local/www/nextcloud/config/config.php 
```

**Add the following to your config.php:**

```php
  'filelocking.enabled' => true,
  'memcache.local' => '\OC\Memcache\Redis',
  'memcache.locking' => '\OC\Memcache\Redis',
  'distributed' => '\\OC\\Memcache\\Redis',
  'redis' => array(
       'host' => '/var/run/redis/redis.sock',
       'port' => 0,
       'timeout' => 0.0,
        ),
```

**Start Redis:**

```shell
sudo service redis start
```

**Restart php-fpm to enable caching:**

```shell
sudo service php-fpm reload 
```

---

**Fix Errors Nextclound compalins about:**

**Set your Phone Region:**	

```shell
sudo vim /usr/local/www/nextcloud/config/config.php
```

```php
  'default_phone_region' => 'US',
```


---

# E-Mail

**Set up E-Mail for status notifications and password resets:**

**Option 1: In the WebGUI:**

Outlook:

| Option | Value |
|---|---|
| Send Mode | SMTP |
| Encryption | STARTTLS |
| From address | firstname.lastname `@` outlook.com |
| Authentication method | None |
| Authentication required | ☑️ |
| Server address | SMTP.office365.com `:` 587 |
| Credentials | firstname.lastname@outlook.com, `*****` |

GMail:

| Option | Value |
|---|---|
| Send Mode | SMTP |
| Encryption | SSL/TLS |
| From address | firstname.lastname `@` gmail.com |
| Authentication method | Login |
| Authentication required | ☑️ |
| Server address | smtp.gmail.com `:` 465 |
| Credentials | firstname.lastname@gmail.com, `*****` |

**Option 2: edit config.php directly:**

```php
  'mail_smtpmode' => 'smtp',
  'mail_smtpsecure' => 'tls',
  'mail_sendmailmode' => 'smtp',
  'mail_smtphost' => 'SMTP.office365.com',
  'mail_smtpport' => '587',
  'mail_from_address' => 'firstname.lastname',
  'mail_domain' => 'outlook.com',
  'mail_smtpauth' => 1,
  'mail_smtpname' => 'firstname.lastname@outlook.com',
  'mail_smtppassword' => 'abcdefghijklmnop',
```

---

Installing and testing the upgrade of Nextcloud 24 to 25 from the Nextcloud WebGUI: Successful on 2023.02.28
