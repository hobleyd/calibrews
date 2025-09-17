#!/usr/bin/env python3
"""
HTTPS API server to serve book data from a Calibre SQLite database
"""

import json
import ipaddress
import logging
import os
import requests
import socket
import sqlite3
import ssl
import sys
import urllib.parse

from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from OpenSSL import crypto
from typing import List, Dict, Any, Optional
from zeroconf import ServiceInfo, Zeroconf

# Configuration
PORT = 10444
CERT_FILE = os.path.join(os.getenv("SSL_DIR", "/etc/ssl"), os.getenv("SSL_FULLCHAIN",   "fullchain.crt"))
KEY_FILE  = os.path.join(os.getenv("SSL_DIR", "/etc/ssl"), os.getenv("SSL_PRIVATE_KEY", "private/private.key"))
CALIBRE_LIBRARY = os.getenv("CALIBRE_LIBRARY", "/books")
DATABASE_PATH = os.path.join(CALIBRE_LIBRARY, "metadata.db")
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BookAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for book API."""
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests for book data."""
        try:
            # Parse URL and query parameters
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            query_params = urllib.parse.parse_qs(parsed_path.query)
            
            if path == "/books":
                self.handle_books_request(query_params)
            elif path.startswith("/book/"):
                uuid = path[6:]
                self.handle_book_file_request(uuid)
            elif path.startswith("/count/"):
                [last_modified, limit] = path[7:].split('/')
                logger.debug(f'last_modified: !{last_modified}/{limit}!')
                self.handle_count_request(int(last_modified), int(limit))
            elif path.startswith("/tags/"):
                uuid = path[6:]
                self.handle_tags_request(uuid)
            elif path == "/" or path == "/health":
                self.handle_health_check()
            else:
                self.send_error(404, f"{path} Not Found with {query_params}")
                
        except Exception as e:
            logger.error(f"Error processing GET request: {e}")
            self.send_error(500, f"Internal server error: {e}")

    def do_PUT(self):
        """Handle PUT requests with JSON payload."""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))

            if content_length == 0:
                self.send_error(400, "No content provided")
                return

            # Read the request body
            request_body = self.rfile.read(content_length)

            # Parse JSON
            try:
                json_data = json.loads(request_body.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                self.send_error(400, f"Invalid JSON: {e}")
                return

            # Print the received data
            self.process_books_data(json_data)

            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            # Count books in response
            book_count = len(json_data) if isinstance(json_data, list) else 1
            response = {"status": "success", "message": f"Received {book_count} book(s)"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

        except Exception as e:
            logger.error(f"Error processing request: {e}")
            self.send_error(500, f"Internal server error: {e}")

    def get_book_path(self, uuid: str) -> Optional[str]:
        """Get book title from database for prettier download filename."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()

            cursor.execute("SELECT path || '/' || name || '.' || LOWER(format) FROM books JOIN data ON books.id = data.book WHERE format = 'epub' and uuid = ?", (uuid,))
            row = cursor.fetchone()

            conn.close()

            if row and row[0]:
                return row[0]
            return None

        except sqlite3.Error as e:
            logger.warning(f"Could not get book path for UUID {uuid}: {e}")
            return None

    def handle_count_request(self, last_modified: int, limit: int):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT title, author_sort, unixepoch(last_modified) as last_modified, COUNT(*) OVER() AS count
              FROM books
             WHERE datetime(last_modified, 'localtime') >= datetime(?, 'unixepoch')
             ORDER BY unixepoch(last_modified) DESC
             LIMIT ?
             """, (last_modified, limit))
        rows = cursor.fetchall()

        response = {'count': 0, 'book': []}
        if len(rows) > 0:
            books = []
            for row in rows:
                books.append({
                    'title': row['title'],
                    'author': row['author_sort'],
                    'last_modified': int(row['last_modified'])
                })

            response = {
                'count': int(rows[0]['count']),
                'books': books,
            }
        conn.close()

        logger.debug(f"returning the count object: {response}")
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

    def handle_health_check(self):
        """Handle health check endpoint."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "running",
            "message": "Book API server is running",
            "timestamp": datetime.now().isoformat(),
            "endpoints": {
                "/books": "GET books with optional parameters: last_modified, limit, offset",
                "/books": "PUT update Book data in Calibre!",
                "/book/<uuid>": "GET download EPUB file",
                "/count/<last_modified>": "GET number of books modified since the specific time (int secs since 1970)",
                "/tags/<uuid>": "GET tags for book specified by UUID",
                "/health": "Get this message"
            }
        }
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))
    
    def handle_book_file_request(self, uuid: str):
        """Handle /book/{uuid} endpoint to serve EPUB files."""
        try:
            # Validate UUID (basic validation)
            if not uuid or len(uuid.strip()) == 0:
                self.send_error(400, "Invalid UUID")
                return

            # Sanitize UUID to prevent directory traversal
            uuid = uuid.strip()
            if '..' in uuid or '/' in uuid or '\\' in uuid:
                self.send_error(400, "Invalid UUID format")
                return

            # Get book title from database for filename (optional)
            book_path = self.get_book_path(uuid)
            epub_path = os.path.join(CALIBRE_LIBRARY, book_path)

            # Check if file exists
            if not os.path.exists(epub_path):
                logger.warning(f"EPUB file not found: {epub_path}")
                self.send_error(404, f"Book file not found for UUID: {uuid}")
                return

            # Check if it's actually a file (not a directory)
            if not os.path.isfile(epub_path):
                logger.warning(f"Path is not a file: {epub_path}")
                self.send_error(404, f"Book file not found for UUID: {uuid}")
                return

            # Get file size
            file_size = os.path.getsize(epub_path)
            download_filename = f"{uuid}.epub"

            # Send file
            self.send_response(200)
            self.send_header('Content-Type', 'application/epub+zip')
            self.send_header('Content-Length', str(file_size))
            self.send_header('Content-Disposition', f'attachment; filename="{download_filename}"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            # Stream file in chunks
            with open(epub_path, 'rb') as epub_file:
                chunk_size = 8192
                while True:
                    chunk = epub_file.read(chunk_size)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

            logger.info(f"Served EPUB file: {epub_path} ({file_size} bytes)")

        except FileNotFoundError:
            logger.error(f"EPUB file not found: {epub_path}")
            self.send_error(404, f"Book file not found for UUID: {uuid}")
        except PermissionError:
            logger.error(f"Permission denied accessing EPUB file: {epub_path}")
            self.send_error(403, "Permission denied")
        except Exception as e:
            logger.error(f"Error serving EPUB file for UUID {uuid}: {e}")
            self.send_error(500, f"Internal server error: {e}")

    def handle_books_request(self, query_params: Dict[str, List[str]]):
        """Handle /books endpoint."""
        try:
            # Extract parameters
            last_modified = int(self.get_param(query_params, 'last_modified', '0'))
            limit = int(self.get_param(query_params, 'limit', str(DEFAULT_LIMIT)))
            offset = int(self.get_param(query_params, 'offset', '0'))
            
            # Validate parameters
            if limit > MAX_LIMIT:
                limit = MAX_LIMIT
            if limit < 1:
                limit = DEFAULT_LIMIT
            if offset < 0:
                offset = 0
            
            # Query database
            books = self.query_books(last_modified, limit, offset)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS support
            self.end_headers()

            self.wfile.write(json.dumps(books, indent=2).encode('utf-8'))
            
            logger.info(f"Served {len(books)} books (last_modified>={last_modified}, limit={limit}, offset={offset})")
            
        except ValueError as e:
            logger.error(f"Invalid parameter: {e}")
            self.send_error(400, f"Invalid parameter: {e}")
        except Exception as e:
            logger.error(f"Error handling books request: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_tags_request(self, uuid: str):
        """Handle /tags/{uuid} endpoint to get tags for a book."""
        try:
            # Validate UUID (basic validation)
            if not uuid or len(uuid.strip()) == 0:
                self.send_error(400, "Invalid UUID")
                return

            # Sanitize UUID
            uuid = uuid.strip()
            if '..' in uuid or '/' in uuid or '\\' in uuid:
                self.send_error(400, "Invalid UUID format")
                return

            # Query database for tags
            response = self.query_book_tags(uuid)

            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS support
            self.end_headers()

            self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))

            logger.info(f"Served {len(response)} tags for book UUID: {uuid}")

        except Exception as e:
            logger.error(f"Error handling tags request for UUID {uuid}: {e}")
            self.send_error(500, f"Internal server error: {e}")

    def get_param(self, query_params: Dict[str, List[str]], param_name: str, default_value: str) -> str:
        """Extract parameter from query string with default."""
        if param_name in query_params and query_params[param_name]:
            return query_params[param_name][0]
        return default_value

    def process_books_data(self, books_data):
        """Print the books data - handles both single book and list of books."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Handle both single book and list of books
        if isinstance(books_data, list):
            book_list = books_data
        else:
            book_list = [books_data]

        book_count = len(book_list)

        logger.info(f"{book_count} book(s) received - {timestamp}")
        logger.debug("RAW JSON:")
        logger.debug(json.dumps(books_data, indent=2))

        # Connect to database
        conn = sqlite3.connect(DATABASE_PATH)
        try:
            conn.execute("BEGIN")  # or conn.begin()
            cursor = conn.cursor()

            # Delete the trigger
            cursor.execute(f"DROP TRIGGER IF EXISTS books_update_trg;")

            # Process each book!
            for i, book_data in enumerate(book_list, 1):
                logger.debug(f"processing {book_data}")
                self.process_single_book(book_data, i, book_count, cursor)

            # Recreate the trigger
            trigger_definition = """
            CREATE TRIGGER books_update_trg
            AFTER UPDATE ON books
            BEGIN
            UPDATE books SET sort=title_sort(NEW.title)
                         WHERE id=NEW.id AND OLD.title <> NEW.title;
            END;
            """
            cursor.execute(trigger_definition)

            # Commit the transaction (if successful)
            conn.commit()
            logger.info("Transaction committed successfully.")

        except sqlite3.Error as e:
            # Rollback the transaction (if an error occurred)
            if conn:
                conn.rollback()
                logger.error(f"Transaction rolled back due to error: {e}")
            else:
                logger.error(f"Error occurred before connection: {e}")

        finally:
            # Close the connection
            if conn:
                conn.close()

        logger.info(f"{'='*80}")
        logger.info(f"✅  Successfully processed {book_count} book(s)")
        logger.info(f"{'='*80}\n")

        # Also log to the logger
        logger.info(f"Received data for {book_count} book(s)")

    def process_single_book(self, book_data: Dict[str, Any], book_num: int, total_books: int, cursor):
        """Update the Calibre DB with the updated values."""
        uuid = book_data.get('UUID', 0)

        logger.debug('process_single_book: Is_Read')
        is_read = book_data.get('Is_read', False)
        cursor.execute("""
            INSERT INTO custom_column_3 (book, value)
            VALUES ((SELECT id FROM books WHERE uuid = :uuid), :is_read)
            ON CONFLICT (book) DO UPDATE SET value = excluded.value;
        """, {"uuid": uuid, "is_read": is_read})

        logger.debug('process_single_book: Last_read')
        last_read = book_data.get('Last_read', 0)
        cursor.execute("""
            INSERT INTO custom_column_4 (book, value)
            VALUES ((select id from books where uuid = :uuid), datetime(:last_read, 'unixepoch', 'localtime'))
            ON CONFLICT (book) DO UPDATE SET value = excluded.value;
        """, {"uuid": uuid, "last_read": last_read})

        logger.debug('process_single_book: Future Reads')
        cursor.execute("""
            DELETE from books_tags_link
            WHERE book in (select id from books where uuid = :uuid)
              AND tag in (select id from tags where name = 'Future Reads');
        """, {"uuid": uuid})

        logger.debug('process_single_book: Last_modified')
        last_mod = book_data.get('Last_modified', 0)
        cursor.execute("""
            UPDATE books
               SET last_modified = datetime(:last_mod, 'unixepoch', 'localtime')
             WHERE uuid = :uuid;
        """, {"uuid": uuid, "last_mod": last_mod})

    def query_books(self, last_modified: int, limit: int, offset: int) -> List[Dict[str, Any]]:
        sql_query = """
        select uuid,
               title,
               coalesce(s.sort, "") as series,
               coalesce(series_index, 0) as series_index,
               author_sort as author,
               coalesce(r.rating, 0) as rating,
               coalesce(cc3.value, 0) as is_read,
               coalesce(strftime('%s', cc4.value), 0) as last_read,
               strftime('%s', last_modified, 'localtime') as last_mod,
               coalesce(c.text, "") as blurb
        from books
        left join custom_column_3 cc3
               on cc3.book = books.id
        left join custom_column_4 cc4
               on cc4.book = books.id
        left join books_series_link bsl
               on bsl.book = books.id
        left join series s
               on s.id = bsl.series
        left join comments c
               on c.book = books.id
        left join books_ratings_link brl
               on brl.book = books.id
        left join ratings r
               on r.id = brl.id
        where datetime(last_modified, 'localtime') >= datetime(?, 'unixepoch')
        limit ? offset ?
        """
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Execute query with parameters
            cursor.execute(sql_query, (last_modified, limit, offset))
            rows = cursor.fetchall()
            
            books = []
            for row in rows:
                book = self.convert_row_to_book_json(row)
                books.append(book)
            
            conn.close()
            return books
            
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            raise Exception(f"Database error: {e}")
    
    def query_book_tags(self, uuid: str):
        """Query tags for a specific book from the database."""

        sql_query = """
        select tags.id, tags.name
        from books, tags, books_tags_link btl
        where uuid = ?
          and books.id = btl.book
          and tags.id = btl.tag
        """

        try:
            conn = sqlite3.connect(DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Execute query with UUID parameter
            cursor.execute(sql_query, (uuid,))
            rows = cursor.fetchall()

            # Extract tag names
            tags = []
            for row in rows:
                tag_json = {
                    "id": row['id'],
                    "tag": row['name'],
                }
                tags.append(tag_json)

            logger.info(tags)
            conn.close()

            return tags

        except Exception as e:
            logger.error(f"Unexpected error querying tags for UUID {uuid}: {e}")
            raise

    def convert_row_to_book_json(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert database row to the required JSON format."""
        
        # Convert string timestamps to integers
        last_read = 0
        if row['last_read']:
            try:
                last_read = int(row['last_read'])
            except (ValueError, TypeError):
                last_read = 0
        
        last_mod = 0
        if row['last_mod']:
            try:
                last_mod = int(row['last_mod'])
            except (ValueError, TypeError):
                last_mod = 0
        
        # Convert rating (handle potential null/different scales)
        rating = 0
        if row['rating']:
            try:
                rating = int(row['rating'])
            except (ValueError, TypeError):
                rating = 0
        
        # Convert is_read to boolean
        is_read = False
        if row['is_read']:
            try:
                is_read = bool(int(row['is_read']))
            except (ValueError, TypeError):
                is_read = False
        
        # Convert series_index to float
        series_index = 0.0
        if row['series_index']:
            try:
                series_index = float(row['series_index'])
            except (ValueError, TypeError):
                series_index = 0.0
        
        authors = row['author'].split('&')
        authors = [{'name': author.strip()} for author in authors]

        book_json = {
            "UUID": row['uuid'] or '',
            "Title": row['title'] or '',
            "Series": { 'series': row['series'] or ''},
            "Series_index": series_index,
            "Author": authors or [],
            "Rating": rating,
            "Is_read": is_read,
            "Last_read": last_read,
            "Last_modified": last_mod,
            "Blurb": row['blurb'] or '',
            "Tags": self.query_book_tags(row['uuid'])
        }
        
        return book_json
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def create_ssl_context():
    """Create SSL context for HTTPS server."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    try:
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        logger.info("SSL certificate loaded successfully")
        return context
    except Exception as e:
        logger.error(f"Failed to load SSL certificate: {e}")
        sys.exit(1)

def create_cert_if_required():
    global CERT_FILE, KEY_FILE
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        CERT_FILE='selfsigned.crt'
        KEY_FILE='private.key'

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)

        cert = crypto.X509()
        cert.get_subject().C = "CN"
        cert.get_subject().ST = "ST"
        cert.get_subject().L = "L"
        cert.get_subject().O = "O"
        cert.get_subject().OU = "OU"
        cert.get_subject().CN = "CN"
        cert.get_subject().emailAddress = "emailAddress"
        cert.set_serial_number(0)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(KEY_FILE, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    logger.info(f'got IP address: {IP}')
    return IP

def register_service(service_name, port, service_type="_http._tcp.local."):
    """Register service with Zeroconf"""
    zeroconf = Zeroconf()

    ip_addr = get_local_ip()
    info = ServiceInfo(
        service_type,
        f"{service_name}.{service_type}",
        addresses=[socket.inet_aton(ip_addr)],
        port=port,
        properties={
            'description': 'Calibre Web Service',
            'version': '1.0',
            'server': ip_addr,
            'port': PORT
        }
    )

    zeroconf.register_service(info)
    logging.info(f"Service registered as {info}")
    return zeroconf, info

def main():
    logger.info(f"🚀 Starting Calibre API HTTPS server on port {PORT}")

    if not os.path.exists(DATABASE_PATH):
        logger.error(f"Database file not found: {DATABASE_PATH}")
        #sys.exit(1)

    zeroconf, service_info = register_service("calibre-service", PORT)
    try:
        # Create HTTP server
        httpd = HTTPServer(('', PORT), BookAPIHandler)
        
        # Create and apply SSL context
        create_cert_if_required()
        ssl_context = create_ssl_context()
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        
        logger.info(f"HTTPS API server started on port {PORT}")
        logger.info(f"\n✅ Server running at https://localhost:{PORT}")
        logger.info("📚 Endpoints:")
        logger.info(f"   GET /books?last_modified=<timestamp>&limit=<num>&offset=<num>")
        logger.info(f"   GET /book/<uuid>  - Download EPUB file")
        logger.info(f"   GET /count/last_modified - Get number of books")
        logger.info(f"   GET /tags/<uuid> - Get tags for book")
        logger.info(f"   GET /health")
        logger.info(f"   PUT /books")
        logger.info("🔍 Use Ctrl+C to stop the server\n")
        
        # Start serving
        httpd.serve_forever()
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        logger.info("\n👋 Server stopped")
    except PermissionError:
        logger.error(f"Permission denied. Port {PORT} requires root privileges.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)
    finally:
        zeroconf.unregister_service(service_info)
        zeroconf.close()

if __name__ == "__main__":
    main()
    # TODO: exit when IP address changes.

