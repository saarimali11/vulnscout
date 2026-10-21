# Demo file for VS005 and VS006. Six vulnerable lines, then safe ones.
# This file is only scanned, never run.
import hashlib
import hashlib as hl
import ssl
from hashlib import md5 as quick_hash

import requests # type: ignore  (not needed to scan; may not be installed)

data = b"hello"

# vulnerable  
hashlib.md5(data) # VS005: plain call
hl.sha1(data) # VS005: module alias
quick_hash(data) # VS005: from-import alias
hashlib.new("MD5", data) # VS005: algorithm by name
requests.get("https://example.com", verify=False) # VS006: verify off
ssl._create_unverified_context() # VS006: unverified context

# safe 
hashlib.sha256(data)
hashlib.md5(data, usedforsecurity=False) # explicitly not for security
requests.get("https://example.com")
requests.get("https://example.com", verify=True)