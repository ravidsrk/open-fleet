- **Run artifacts no longer bury the live code in searches** (#761). `docs/runs/.ignore` hides
  the frozen artifacts from ripgrep-style tools while every run report and index row stays
  searchable: hits for `verify.py` fell from 608 files (358 of them artifacts) to 335. git never
  reads the file, so nothing that binds or hashes an artifact changes.
