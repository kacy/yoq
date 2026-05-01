id: nj8usqhaks6kkewaj3pbp0arfh4281me25bl7tf9das1vbqv
name: sqlite
main: sqlite.zig
license: MIT
description: Thin SQLite wrapper
c_include_dirs:
  - c
c_source_files:
  - c/workaround.c
dependencies:
- src: http https://sqlite.org/2025/sqlite-amalgamation-3490200.zip sha256-921fc725517a694df7df38a2a3dfede6684024b5788d9de464187c612afb5918
  license: blessing
  c_include_dirs:
    - sqlite-amalgamation-3490200
  c_source_files:
    - sqlite-amalgamation-3490200/sqlite3.c
