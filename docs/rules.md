# Rules

| ID | OWASP category | Severity | What it detects |
|----|----------------|----------|-----------------|
| VS001 | A03:2021-Injection | High | `eval()` / `exec()` calls |
| VS002 | A03:2021-Injection | High | `subprocess` with `shell=True`, `os.system`, `os.popen` |
| VS003 | A03:2021-Injection | High | SQL built with f-strings, `+`, `%`, or `.format()` passed to `execute()` |
| VS004 | A07:2021-Identification and Authentication Failures | High | Hardcoded passwords, API keys, tokens, and private keys (by name, known pattern, or entropy) |
| VS005 | A02:2021-Cryptographic Failures | Medium | `hashlib.md5` / `hashlib.sha1` / `hashlib.new("md5")` (skips `usedforsecurity=False`) |
| VS006 | A02:2021-Cryptographic Failures | High | `verify=False` on any call, `ssl._create_unverified_context()` |
| VS007 | A08:2021-Software and Data Integrity Failures | High | `pickle`/`dill`/`marshal` loads, `shelve.open`, `pandas.read_pickle`, `yaml.load` without a safe Loader, `numpy.load(allow_pickle=True)` |

## VS001: eval/exec

`eval` and `exec` run strings as code, so untrusted input becomes code execution.

```python
# Bad
result = eval(user_input)

# Better: parse plain data only
import ast
result = ast.literal_eval(user_input)
```

## VS002: shell injection

Passing a user-influenced string through the shell lets an attacker append commands.

```python
# Bad
subprocess.run("ls " + folder, shell=True)

# Better: a list of args never goes through the shell
subprocess.run(["ls", folder])
```

## VS003: SQL injection

Building a query by pasting values into the text lets an attacker change its meaning
(`name = "x' OR '1'='1"` returns every row).

```python
# Bad
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Better: parameterized, the driver inserts the value safely
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

Also tracks a query variable built dynamically and executed later in the same function.
Does not follow strings passed between functions.

## VS004: hardcoded secrets

Secrets in source code are readable by anyone with repo access, and git history keeps
them even after you delete the line.

```python
# Bad
password = "hunter2"
connect(user="admin", password="letmein123")

# Better: read from the environment (or a secrets manager)
import os
password = os.environ["DB_PASSWORD"]
```

Detected three ways: a suspicious name (`password`, `api_key`, `secret`, `token`...) with a
non-placeholder string value, strings shaped like known credentials (AWS, GitHub, Slack, private
key headers), and long random-looking strings (Shannon entropy of 4.5+ bits/char).

Known limit: `token_type = "bearer"` is flagged because the name contains `token`.
Inline suppression is planned.


## VS005: weak hashes

MD5 and SHA-1 have known collision attacks, so they shouldn't protect passwords,
signatures, or integrity.

```python
# Bad
hashlib.md5(password.encode())

# Better
hashlib.sha256(data)                    # general hashing
# bcrypt / argon2 for passwords

# Fine: a checksum or cache key that isn't security related
hashlib.md5(data, usedforsecurity=False)
```

Understands import aliases (`import hashlib as h`, `from hashlib import md5`).

## VS006: disabled TLS verification

`verify=False` means the client accepts any certificate, so a man-in-the-middle can
read and modify "secure" traffic.

```python
# Bad
requests.get(url, verify=False)

# Better
requests.get(url)                       # verifies by default
requests.get(url, verify="ca.pem")      # or point at your own CA bundle
```

Not covered yet: `ctx.check_hostname = False` and `ctx.verify_mode = ssl.CERT_NONE`.

## VS007: unsafe deserialization

Formats like pickle rebuild Python objects, so a crafted file can run any code as it loads.
If the data could come from a user, a download, or a shared folder, that's remote code execution.

```python
# Bad
obj = pickle.load(f)
config = yaml.load(text)

# Better
obj = json.load(f)                  # plain data only
config = yaml.safe_load(text)       # or yaml.load(text, Loader=yaml.SafeLoader)
```

Flags every `pickle.load`, even on files you wrote yourself, because the scanner can't
know where data came from. Known limit: a Loader stored in a variable isn't checked.