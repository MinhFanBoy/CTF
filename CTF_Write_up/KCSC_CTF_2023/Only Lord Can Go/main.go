package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
)

func main() {
    fmt.Println(" _  __  ___  ___   ___   _      ___   _____  _____  ___  ___ __  __ ")
    fmt.Println("| |/ / / __|/ __| / __| | |    / _ \\ |_   _||_   _|| __|| _ \\\\ \\ / / ")
    fmt.Println("| ' < | (__ \\__ \\| (__  | |__ | (_) |  | |    | |  | _| |   / \\ V /  ")
    fmt.Println("|_|\\_\\ \\___||___/ \\___| |____| \\___/   |_|    |_|  |___||_|_\\  |_|   ")
	fmt.Println()
	
	var a,b,c,d,e,y,m int
	m = 1<<31 - 1
	a = rand.Intn(m)
	b = rand.Intn(m)
	c = rand.Intn(m)
	d = rand.Intn(m)
	e = rand.Intn(m)
	y = rand.Intn(m)

	fmt.Println("I will give u 5 lucky numbers :>")
	for i:=1; i<=5; i++ {
		y = (a*d + b*e + c) % m
		fmt.Printf("Lucky number %v: %v \n", i, y)
		e = d
		d = y
	}
	fmt.Println()

	fmt.Println("Now show off your guessing skills, ego ._.")
	var guess string
	for i:=1; i<=23; i++ {
		y = (a*d + b*e + c) % m
		fmt.Print("Guess: ")
		fmt.Scan(&guess)
		numGuess, _ := strconv.Atoi(guess)
		if numGuess == y {
			fmt.Printf("Nai xuw !!! Remain: %v/23\n", 23-i)
		} else {
			fmt.Println("Luck is only for those who try, if you don't understand that, then get out !!!")
			return
		}
		e = d
		d = y
	}

	fmt.Println("WOW, I rly want how do u can guess all correctly, plz sharing w me :<")
	content, _ := ioutil.ReadFile("flag.txt")
	fmt.Println(string(content))
}
