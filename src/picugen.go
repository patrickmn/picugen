package main

import (
	"crypto/hmac"
	"crypto/md4"
	"crypto/md5"
	"crypto/ripemd160"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

const (
	version   = "1.0"
	chunkSize = 32768 // Read files in 32KB chunks
)

var (
	alg  *string = flag.String("a", "md5", "algorithm")
	str  *string = flag.String("s", "", "string to hash instead of file")
	key  *string = flag.String("k", "", "key (for hashes that use a key, e.g. HMAC)")
	salt *string = flag.String("salt", "", "salt")
)

var (
	algDescs = map[string]string{
		"adler32":         "Adler-32 checksum (RFC 1950)",
		"crc32":           "32-bit cyclic redundancy check (CRC-32) checksum (defaults to IEEE polynomial)",
		"crc32ieee":       "CRC-32 using the IEEE polynomial (0xedb88320)",
		"crc32castagnoli": "CRC-32 using the Castagnoli polynomial (0x82f63b78)",
		"crc32koopman":    "CRC-32 using the Koopman polynomial (0xeb31d82e)",
		"crc64":           "64-bit cyclic redundancy check (CRC-64) checksum (defaults to ISO polynomial)",
		"crc64iso":        "CRC-64 using the ISO polynomial (0xD800000000000000)",
		"crc64ecma":       "CRC-64 using the ECMA polynomial (0xC96C5795D7870F42)",
		"fnv":             "FNV-1 non-cryptographic hash (defaults to fnv32)",
		"fnv32":           "32-bit FNV-1",
		"fnv32a":          "32-bit FNV-1a",
		"fnv64":           "64-bit FNV-1",
		"fnv64a":          "64-bit FNV-1a",
		"hmac":            "Keyed-Hash Message Authentication Code (HMAC) (requires -k <key>) (defaults to SHA-256)",
		"hmacmd5":         "HMAC using MD5 (requires -k <key>)",
		"hmacsha1":        "HMAC using SHA-1 (requires -k <key>)",
		"hmacsha256":      "HMAC using SHA-256 (requires -k <key>)",
		"hmacsha512":      "HMAC using SHA-512 (requires -k <key>)",
		"md4":             "MD4 hash (RFC 1320)",
		"md5":             "MD5 hash (RFC 1321)",
		"ripemd160":       "RIPEMD-160 hash",
		"sha1":            "SHA-1 hash (RFC 3174)",
		"sha224":          "SHA-224 hash (FIPS 180-2)",
		"sha256":          "SHA-256 hash (FIPS 180-2)",
		"sha384":          "SHA-384 hash (FIPS 180-2)",
		"sha512":          "SHA-512 hash (FIPS 180-2)",
	}
)

func GetGenerator(a string) (hash.Hash, os.Error) {
	var g hash.Hash
	switch a {
	default:
		return md5.New(), os.NewError("Invalid algorithm")
	case "adler32":
		g = adler32.New()
	case "crc32", "crc32ieee":
		g = crc32.New(crc32.MakeTable(crc32.IEEE))
	case "crc32castagnoli":
		g = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "crc32koopman":
		g = crc32.New(crc32.MakeTable(crc32.Koopman))
	case "crc64", "crc64iso":
		g = crc64.New(crc64.MakeTable(crc64.ISO))
	case "crc64ecma":
		g = crc64.New(crc64.MakeTable(crc64.ECMA))
	case "fnv", "fnv32":
		g = fnv.New32()
	case "fnv32a":
		g = fnv.New32a()
	case "fnv64":
		g = fnv.New64()
	case "fnv64a":
		g = fnv.New64a()
	case "hmac", "hmacsha256":
		g = hmac.NewSHA256([]byte(*key))
	case "hmacmd5":
		g = hmac.NewMD5([]byte(*key))
	case "hmacsha1":
		g = hmac.NewSHA1([]byte(*key))
	case "hmacsha512":
		g = hmac.New(sha512.New, []byte(*key))
	case "md4":
		g = md4.New()
	case "md5":
		g = md5.New()
	case "ripemd160":
		g = ripemd160.New()
	case "sha1":
		g = sha1.New()
	case "sha224":
		g = sha256.New224()
	case "sha256":
		g = sha256.New()
	case "sha384":
		g = sha512.New384()
	case "sha512":
		g = sha512.New()
	}
	return g, nil
}

func HashString(gen hash.Hash, s string) string {
	gen.Write([]byte(s))
	return fmt.Sprintf("%x", gen.Sum())
}

func HashFile(gen hash.Hash, f io.Reader) (string, os.Error) {
	buf := make([]byte, chunkSize)
	gen.Write([]byte(*salt))
	for {
		bytesRead, err := f.Read(buf)
		if err != nil {
			if err == os.EOF && bytesRead == 0 { // Empty file
				gen.Write([]byte(""))
			} else {
				return "", err
			}
		} else {
			gen.Write(buf[:bytesRead])
		}
		if bytesRead < chunkSize { // EOF
			break
		}
	}
	return fmt.Sprintf("%x", gen.Sum()), nil
}

func Usage() {
	fmt.Println("Usage:", os.Args[0], "[-a <algorithm>] [-salt <salt>] -s <string to hash>/-f <file to hash>\n")
	fmt.Println("Examples:")
	fmt.Println(" ", os.Args[0], "-a md5 document.txt               ", "Generate MD5 hash of a file")
	fmt.Println(" ", os.Args[0], "-a md5 *                          ", "Generate MD5 hash of all files in folder")
	fmt.Println(" ", os.Args[0], "-a sha1 -s hello world            ", "Generate SHA-1 hash of a string")
	fmt.Println(" ", os.Args[0], "-a sha1 -salt s4lt -s hello world ", "Generate salted SHA-1 hash of a string")
	fmt.Println("")
	fmt.Println("Available algorithms (default is MD5):")
	mk := make([]string, len(algDescs))
	i := 0
	for k, _ := range algDescs {
		mk[i] = k
		i++
	}
	sort.Strings(mk)
	for _, v := range mk {
		fmt.Printf("  %-15s %s\n", v, algDescs[v])
	}
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 && *str == "" {
		Usage()
		return
	}
	*alg = strings.ToLower(*alg)
	gen, err := GetGenerator(*alg)
	if err != nil {
		log.Fatalln(err)
	}
	if *str == "" { // Hash file(s)
		for _, path := range flag.Args() {
			var res string
			f, err := os.Open(path)
			defer f.Close()
			if err != nil {
				res = err.String()
			} else {
				h, err := HashFile(gen, f)
				if err != nil {
					res = err.String()
				} else {
					res = h
				}
			}
			fmt.Println(res, "", path)
			gen.Reset()
		}
	} else { // Hash string
		fmt.Println(HashString(gen, *salt+*str))
	}
}
