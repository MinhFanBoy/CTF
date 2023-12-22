# Crypto

---

**_Description:_**

Ever heard of the 5x5 secret message system? If not, basically it's a 5x5 grid with all letters of the alphabet in order, without k because c is represented to make the k sound only. Google it if you need to. A letter is identified by Row-Column. All values are in caps. Try: 1-3,4-4,2-1,{,4-4,2-3,4-5,3-2,1-2,4-3,_,4-5,3-5,}

---

When search google, i find alphabet 5x5 (it without k). Copy it and write code, if x is number i split it to 2 pieces and print, else i print it to display.


    flag = "1-3,4-4,2-1,{,4-4,2-3,4-5,3-2,1-2,4-3,_,4-5,3-5,}"
    
    lst =[
        ["a", "b", "c", "d", "e"],
        ["f", "g", "h", "i", "j"],
        ["l", "m", "n", "o", "p"],
        ["q", "r", "s", "t", "u"],
        ["v", "w", "x", "y", "z"]]
    flag = flag.split(",")
    for x in flag:
        try:
            t = x.split("-")
            print(lst[int(t[0]) - 1][int(t[1]) - 1], end = "")
        except:
            print(x, end = "")
