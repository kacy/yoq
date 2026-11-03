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
- src: http https://sqlite.org/2026/sqlite-amalgamation-3540100.zip sha256-0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9
  license: blessing
  c_include_dirs:
    - sqlite-amalgamation-3540100
  c_source_files:
    - sqlite-amalgamation-3540100/sqlite3.c
