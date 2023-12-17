# nc 103.162.14.116 14003
from pwn import *
from json import *
s = remote("103.162.14.116", 14003)

def fun(p):
    if len(p) % 2 != 0:
        return "no"
    else:
        stack = []
        for x in p:
            if x == "(":
                stack.append("(")
            else :
                if len(stack) == 0:
                    return "no"
                stack.remove("(")
        if len(stack) == 0:
            return "yes"
        else:
            return "no"

print(s.recv().decode("utf-8"))

while True:
    a = s.recv().decode("utf-8")

    print(a)
    a = a.split(": ")[1]
    a = a.split("\n")[0]
    print(a)
    s.send(bytes(str(fun(a)), encoding = "utf-8"))
    print(s.recv())