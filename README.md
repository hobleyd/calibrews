# Web Services for Calibre

This is a python webservice which allows a limited set of interactions with the Calibre ebook management software.
It is written for [Paladin](https://github.com/hobleyd/paladin), an Android launcher designed for eInk eReaders. But is usable by anyone.

You can install it using Docker, or run it on the command line.

In order to access it remotely, you will need either need to point your own domain to your server, or,
if you don't have your own domain, configure an account with [Dynu](https://www.dynu.com) and follow the instructions below.

1. Register for an account
2. Get the API key (Control Panel -> API Credentials) [here](https://www.dynu.com/en-US/ControlPanel/APICredentials)
3. Set an environment variable called DYNU_API="API Key"
   1. Windows: Edit the calibrews.bat or calibrews.ps1 script and add it in.
   2. MacOS: Edit the calibrews.sh script and add it in.
   3. Linux: Edit the calibrews.sh script and add it in.
   4. Docker: I assume you know how to do this, if you understand Docker.

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
/count/last_modified will show a count of all books channged since the last timestamp
/tags/uuid will get the tags for a specific book
/health will show whether the service is running or not.
PUT /books will allow you to update the last read, last modified or rating.

This relies on having added an Is_read and a Last_read field into Calibre (TODO: document this)
