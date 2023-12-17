import string
import random

alphabet = string.ascii_letters + string.digits + "!{_}?"
ct='ldtdMdEQ8F7NC8Nd1F88CSF1NF3TNdBB1O'
for key in range(len(alphabet)):
    text = ""
    for i in ct:
        
        text += (alphabet[(alphabet.index(i) - key) % len(alphabet)])

    print(f"{text=}")