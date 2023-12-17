# nc 103.162.14.116 14005
from pwn import *
from json import *
s = remote("103.162.14.116", 14005)
a={0:1}
def fun(t: int) -> int:
    if t in a:
        return a[t]
    else:
        if t % 2 == 0:
            a[t] = t * fun(t-1)
            return a[t]
        else:
            a[t] = t + fun(t-1)
            return a[t]

while True:
    print(s.recv())        
    quest = s.recv().decode("utf-8")
    print(quest)
    quest = quest.split("[")[1]
    quest = int(quest.split("]")[0])
    print(quest)
    s.send(bytes(str(fun(quest)), encoding = "utf-8"))
