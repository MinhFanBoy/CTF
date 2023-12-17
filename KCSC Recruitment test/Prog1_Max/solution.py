# nc 103.162.14.116 14002
from pwn import *
from json import *
s = remote("103.162.14.116", 14002)

while True:
    print( s.recv().decode("utf-8"))
    try:
        a = s.recv().decode("utf-8")
        print(a)
        lst = a.split("[")[1]
        lst = lst.split("]")[0]
        lst = [int(x) for x in lst.split(", ")]
        print(lst)
        s.send(bytes(str(max(lst)), encoding = "utf-8"))


    except:

        print(s.recv())