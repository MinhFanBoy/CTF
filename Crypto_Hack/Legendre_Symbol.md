# Crypto Hack

src = [Crypto Hack](https://cryptohack.org/courses/modular/root1/)

---

**_Description_:**

 Given the following 1024 bit prime and 10 integers, find the quadratic residue and then calculate its square root; the square root is your flag. Of the two possible roots, submit the larger one as your answer.

Challenge files:
  - [output.txt](https://cryptohack.org/static/challenges/output_479698cde19aaa05d9e9dfca460f5443.txt)
---

## Solution

Với 2 số trong trường F(Z) thì ta có: 

    Quadratic Residue * Quadratic Residue = Quadratic Residue
    Quadratic Residue * Quadratic Non-residue = Quadratic Non-residue
    Quadratic Non-residue * Quadratic Non-residue = Quadratic Residue

Legendre's Symbol: Nếu a là phần dư bậc 2 trong trường F(p) thì ta có:

    (a / p) ≡ a(p-1)/2 mod p

## Code:

Đầu tiến với list ints thì ta sẽ xem có số nào trong list thỏa mãn là phần dư bậc 2. Dùng hàm for check qua từng phần tử trong list với điều kiện của hàm Legendre.
    
    lst = [ x for x in ints if pow( x, (p-1)//2, p ) == 1]
Ta có dc 1 phần tử trong ints thỏa mãn nên bây giờ ta sẽ bắt đầu tìm x. Với x^2 = lst mod p


có lst = 3 mod 4 nên 

lst = (p+1)/4

và a = a^( (p-1)//2 ) mod p => a^2 = a^( (p+1)//2 ) mod p => a = a^( (p+1)/4 ) mod p thỏa mãn vs lst

vậy nên ta bắt tay vào code thôi!

Code:

    p = 101524035174539890485408575671085261788758965189060164484385690801466167356667036677932998889725476582421738788500738738503134356158197247473850273565349249573867251280253564698939768700489401960767007716413932851838937641880157263936985954881657889497583485535527613578457628399173971810541670838543309159139
    
    lst = 85256449776780591202928235662805033201684571648990042997557084658000067050672130152734911919581661523957075992761662315262685030115255938352540032297113615687815976039390537716707854569980516690246592112936796917504034711418465442893323439490171095447109457355598873230115172636184525449905022174536414781771
    
    print( pow( lst, (p+1)//4, p ) )

>  x = 93291799125366706806545638475797430512104976066103610269938025709952247020061090804870186195285998727680200979853848718589126765742550855954805290253592144209552123062161458584575060939481368210688629862036958857604707468372384278049741369153506182660264876115428251983455344219194133033177700490981696141526
