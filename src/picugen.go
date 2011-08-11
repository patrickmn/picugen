package main

import (
	"crypto/md4"
	"crypto/md5"
	"crypto/ripemd160"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"os"
)

var (
	salt *string = flag.String("s", "", "salt")
)

func GetHash(alg string, s string) string {
	var gen hash.Hash
	switch alg {
	case "md4":
		gen = md4.New()
	case "md5":
		gen = md5.New()
	case "ripemd160":
		gen = ripemd160.New()
	case "sha1":
		gen = sha1.New()
	case "sha224":
		gen = sha256.New224()
	case "sha256":
		gen = sha256.New()
	case "sha384":
		gen = sha512.New384()
	case "sha512":
		gen = sha512.New()
	}
	gen.Write([]byte(*salt + s))
	return fmt.Sprintf("%x", gen.Sum())
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Println("Example:", os.Args[0], "[-s <salt>] <string to hash>")
		return
	}
	algs := []string{
		"md4",
		"md5",
		"ripemd160",
		"sha1",
		"sha224",
		"sha256",
		"sha384",
		"sha512",
	}
	for _, v := range algs {
		fmt.Printf("%-10s %s\n", v, GetHash(v, flag.Arg(0)))
	}
}
