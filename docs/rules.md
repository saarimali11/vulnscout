# Rules

| ID | OWASP category | Severity | What it detects |
|----|----------------|----------|-----------------|
| VS001 | A03:2021-Injection | High | `eval()` / `exec()` calls |
| VS002 | A03:2021-Injection | High | `subprocess` with `shell=True`, `os.system`, `os.popen` |

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