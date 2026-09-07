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
- src: http https://sqlite.org/2026/sqlite-amalgamation-3530400.zip sha256-1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
  license: blessing
  c_include_dirs:
    - sqlite-amalgamation-3530400
  c_source_files:
    - sqlite-amalgamation-3530400/sqlite3.c
