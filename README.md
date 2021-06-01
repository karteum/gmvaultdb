# gmvaultdb
Store emails from a GMvault backup into an sqlite DB and extracts attachments in a dedicated folder

GMvault is a great tool to backup a gmail account (N.B. in my case, I archived the whole dir in squashfs-lzma so I left the eml uncompressed rather than eml.gz).

This program is an attempt to extract data from such a gmvault backup. In particular
* walks through a db/ folder from a GMvault backup (assuming .eml are not gzipped, but support for eml.gz should be easy to add)
* parses the .meta and .eml files, the latter can be MIME with various encoding, attachments, etc.
* stores the emails (header, txt, html, signatures) in an SQLite database. For HTML, the attached images are extracted and inserted as base64 embedded images within the html in order to avoid keeping a separate file
* extracts the other attached files to a dedicated folder (so all the attached files can be accessed directly through the filesystem). If the same file (same name, same md5) has already been extracted, it will not be stored twice. If a file with similar name but different md5 has already been extracted, it will be stored with a different name
* adds a small GUI to walk through the emails and add additional "where" conditions to the SQL query (for the moment it works with plain sqlite including "like" clauses. In the future I will test SQLite's full-text search features)

## Usage
* `gmvault_sql createdb gmvault_backup_dir out_dir` : scans gmvault_backup_dir, and extracts emails (html+text+images) in mails.db and other attachments directly as files in subdirs
* `gmvault_sql gui db_file` : gui (in pyside/qt5) to navigate/search through mails.db (SQL queries are possible)
