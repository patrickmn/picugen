package main

import (
	"code.google.com/p/go.crypto/md4"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	alg       string
	key       string
	salt      string
	hashStr   bool
	groupSame bool
	onlySame  bool
)

func init() {
	flag.StringVar(&alg, "a", "sha256", "algorithm")
	flag.StringVar(&key, "k", "", "key (for hashes that use a key, e.g. HMAC)")
	flag.StringVar(&salt, "salt", "", "salt")
	flag.BoolVar(&hashStr, "s", false, "hash a string")
	flag.BoolVar(&groupSame, "group-same", false, "group files with identical hash digests (buffers output)")
	flag.BoolVar(&onlySame, "only-same", false, "only show files with identical hash digests (enables group-same and buffers output)")
	flag.Parse()
	if onlySame {
		groupSame = true
	}
}

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

func GetHash(a string) (hash.Hash, error) {
	var h hash.Hash
	switch a {
	case "adler32":
		h = adler32.New()
	case "crc32", "crc32ieee":
		h = crc32.New(crc32.MakeTable(crc32.IEEE))
	case "crc32castagnoli":
		h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "crc32koopman":
		h = crc32.New(crc32.MakeTable(crc32.Koopman))
	case "crc64", "crc64iso":
		h = crc64.New(crc64.MakeTable(crc64.ISO))
	case "crc64ecma":
		h = crc64.New(crc64.MakeTable(crc64.ECMA))
	case "fnv", "fnv32":
		h = fnv.New32()
	case "fnv32a":
		h = fnv.New32a()
	case "fnv64":
		h = fnv.New64()
	case "fnv64a":
		h = fnv.New64a()
	case "hmac", "hmacsha256":
		h = hmac.New(sha256.New, []byte(key))
	case "hmacmd5":
		h = hmac.New(md5.New, []byte(key))
	case "hmacsha1":
		h = hmac.New(sha1.New, []byte(key))
	case "hmacsha512":
		h = hmac.New(sha512.New, []byte(key))
	case "md4":
		h = md4.New()
	case "md5":
		h = md5.New()
	case "ripemd160":
		h = ripemd160.New()
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return nil, errors.New("Invalid algorithm")
	}
	return h, nil
}

func HashString(h hash.Hash, s string) string {
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HashFile(h hash.Hash, f io.Reader) (string, error) {
	h.Write([]byte(salt))
	_, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func Usage() {
	fmt.Println("Usage:", os.Args[0], "[-a <algorithm>] [-salt <salt>] [-s <string to hash>] / <file(s) to hash>\n")
	fmt.Println("Examples:")
	fmt.Println(" ", os.Args[0], `-a md5 document.txt               `, "Generate MD5 digest of a file")
	fmt.Println(" ", os.Args[0], `-a md5 *                          `, "Generate MD5 digests of all files in folder")
	fmt.Println(" ", os.Args[0], `-a sha1 -s hello world            `, "Generate SHA-1 digest of a string")
	fmt.Println(" ", os.Args[0], `-a sha1 -salt s4lt -s hello world `, "Generate salted SHA-1 digest of a string")
	fmt.Println(" ", os.Args[0], `-a hmacsha1 -k k3y -s untouched   `, "Generate HMAC of a string using SHA-1")
	fmt.Println("")
	fmt.Println("Available algorithms (default is SHA-256):")
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
	fmt.Println("")
	fmt.Println(`Note: For complex strings, put the string in a file, then run Picugen on
      the file. (Don't add newlines to the file as they will alter the output.)`)
}

func main() {
	if flag.NArg() == 0 {
		Usage()
		return
	}
	args := flag.Args()
	alg = strings.ToLower(alg)
	h, err := GetHash(alg)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if hashStr {
		var s string
		for i, word := range args {
			if i > 0 {
				s += " "
			}
			s += word
		}
		fmt.Println(HashString(h, salt+s))
		return
	}
	var g map[string][]string
	if groupSame {
		// We won't get a lot of identical digests, so reduce allocation
		// by assuming each file/glob will produce a unique digest.
		g = make(map[string][]string, len(args))
	}
	for _, globStr := range flag.Args() {
		// Okay to ignore error here since error just means no matches
		paths, _ := filepath.Glob(globStr)
		for _, path := range paths {
			var res string
			f, err := os.Open(path)
			if err != nil {
				res = err.Error()
			} else {
				h, err := HashFile(h, f)
				if err != nil {
					res = err.Error()
				} else {
					res = h
				}
				f.Close()
			}
			if groupSame {
				g[res] = append(g[res], path)
			} else {
				fmt.Println(res, "", path)
			}
			h.Reset()
		}
	}
	if groupSame {
		for k, v := range g {
			if !onlySame || len(v) > 1 {
				for _, ov := range v {
					fmt.Println(k, "", ov)
				}
			}
		}
	}
}
