import os
import subprocess

user_input = input("expr: ")
result = eval(user_input)
exec("print('hi')")
subprocess.run("ls " + user_input, shell=True)
os.system("echo " + user_input)
subprocess.run(["ls", "-l"])
