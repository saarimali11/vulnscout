# Rules

| ID | OWASP category | Severity | What it detects |
|----|----------------|----------|-----------------|
| VS001 | A03:2021-Injection | High | `eval()` / `exec()` calls |
| VS002 | A03:2021-Injection | High | `subprocess` with `shell=True`, `os.system`, `os.popen` |
| VS003 | A03:2021-Injection | High | SQL built with f-strings, `+`, `%`, or `.format()` passed to `execute()` |

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