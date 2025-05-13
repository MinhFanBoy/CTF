import random
from Crypto.Util.number import getPrime, bytes_to_long

soundtrack = [
    b"House Of The Rising Sun",
    b"the Dock of the Bay",
    b"(Walkin' Thru The) Sleepy City",
    b"Redondo Beach",
    b"Pale Blue Eyes",
    b"Brown Eyed Girl",
    b"Feeling Good",
    b"Aoi Sakana",
    b"Perfect Day"
]

print("Welcome to the song guessing game!")

for i in range(32):
    p = getPrime(512)
    k = random.randint(1, 4096)
    song = random.choice(soundtrack)
    padded_song = song + b"0xff"*(256 - len(song))
    hint = pow(1 + k*p, bytes_to_long(padded_song), p**2)
    
    print(f"p = {p}")
    print(f"hint = {hint}")
    ans = input("Guess the song: ")
    
    if ans == song.decode():
        print("Correct!")
    else:
        print("Wrong! Try again.")
        exit(0)
        
FLAG = open("flag.txt", "r").read()
print("Congratulations! You've guessed all the songs correctly.")
print(f"Flag: {FLAG}")