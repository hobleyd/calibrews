# Web Services for Calibre

This is a python webservice which allows a limited set of interactions with the Calibre ebook management software.
It is written for [Paladin](https://github.com/hobleyd/paladin), an Android launcher designed for eInk eReaders. But is usable by anyone.

You can install it using Docker, or run it on the command line.

If you run it on the command line, Paladin will discover the service running and connect to it if both devices
are running on the same network.

In order to access it remotely, you will need to configure a Cloudflare tunnel, to allow Paladin to hit .
https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
cloudflared tunnel login

If you can provide your own SSL certificate, use environment variables for SSL_DIR, SSL_FULLCHAIN and SSL_PRIVATE_KEY to point to the
folder and the relevant files accordingly. See the .bat, .ps1 or .sh files for an example. If you don't want to provide your own, the
service will create a self-signed certificate and use that. Paladin won't enforce the fact that this is not fully signed which is
slightly less secure, but given this is designed for a single person to use, I don't consider that a major issue.

The API supports the following actions:
```
        GET /books?last_modified=<timestamp>&limit=<num>&offset=<num>
        GET /book/<uuid>
        GET /count/last_modified
        GET /tags/<uuid>
        GET /health
        PUT /books
```

/books will show all books modified since the last timestamp (# seconds since the Unix epoch)
/book/uuid will download a specific book to your device
/count/last_modified will show a count of all books changed since the last timestamp
/tags/uuid will get the tags for a specific book
/health will show whether the service is running or not.
PUT /books will allow you to update the last read, last modified or rating.

This relies on having added an Is_read and a Last_read field into Calibre (TODO: document this)
