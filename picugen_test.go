package main

import (
	"flag"
	"io/ioutil"
	"os"
	"testing"
)

const (
	testStr  = "hello world"
	testSalt = "saltynom"
	testKey  = "shallpass"
	testFile = `This is what a normal
text file might look like. It's really interesting
how the text wraps in the file--like a wonderful carpet.

A wonderful carpet.
`
)

var (
	testStringHashes = [][3]string{
		// alg, expected (but maybe keyed) hash, expected salted hash
		{"adler32", "1a0b045d", "4fb407d4"},
		{"crc32", "0d4a1185", "2a78850e"},
		{"crc32castagnoli", "c99465aa", "9754dd53"},
		{"crc32ieee", "0d4a1185", "2a78850e"},
		{"crc32koopman", "df373d3c", "aaa786de"},
		{"crc64", "b9cf3f572ad9ac3e", "1547441e86be9c8b"},
		{"crc64ecma", "53037ecdef2352da", "6be98883e55910f4"},
		{"crc64iso", "b9cf3f572ad9ac3e", "1547441e86be9c8b"},
		{"fnv", "548da96f", "d1de2160"},
		{"fnv32", "548da96f", "d1de2160"},
		{"fnv32a", "d58b3fa7", "139267c6"},
		{"fnv64", "7dcf62cdb1910e6f", "1a5c7134156d39a0"},
		{"fnv64a", "779a65e7023cd2e7", "928f7aa6eb551166"},
		{"hmac", "c70831e441cbecee9024399ef19faae2d8a4b6084fbca234572649e786215e5b", "d79d4eb769987a45e89ac137a3daec801748218f739b121a80a56171123c9a62"},
		{"hmacmd5", "acfaa637e71a087013767ffcdd2dee6b", "9b2222d3a811e07cf6939d844af5a050"},
		{"hmacsha1", "6d95b7443b6eb2ec3ee4bb2aa3bf81d1998c36b2", "22ed4e68e132666b91f9ad1d767549b4902a0457"},
		{"hmacsha256", "c70831e441cbecee9024399ef19faae2d8a4b6084fbca234572649e786215e5b", "d79d4eb769987a45e89ac137a3daec801748218f739b121a80a56171123c9a62"},
		{"hmacsha512", "0f0b6079200eca3497a40717f3425585508cd129eb208ca1edece2f4a703181df9c3ec5082820d6683a732d0114b9c8d1cd6ec0ff14845e357bdcf07b8d76758", "05e1ed5bfcd6d9b82981eb9f3bdd5c625851dc0b14650f9c116ad8fec856930f30f68594aa9039d2ed569e3920c03d766d7145a97626d8b0738a8419120ec003"},
		{"md4", "aa010fbc1d14c795d86ef98c95479d17", "46cda5abff44dc708e78e8965b154821"},
		{"md5", "5eb63bbbe01eeed093cb22bb8f5acdc3", "6208f8d3f2c59298fa9587e93c814c5c"},
		{"ripemd160", "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f", "321bc05096e9c97cab9fef5efc099efc1b81643d"},
		{"sha1", "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", "585569efc9e9571057aecbc199b86b86f39b4ac6"},
		{"sha224", "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b", "188004ae9f71545998a130355880542e81f13afefbd375eeb8fff206"},
		{"sha256", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "65ad02669e832d12449549f11b46814c4ae9960983ff5822cd9d175b9483f9a8"},
		{"sha384", "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd", "1cf01c88fa2d6b9c7b3d73e37c75ba0a4593f113c58b2a3813ede9f407bdf05a53f20eccda164c6620e3a7373a44d8e2"},
		{"sha512", "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f", "3c4e388ff39154cd2ff294e4ba0a8e146e90b92ef698f1507dfbd94cb2f8c5d84b066cac70553f8dedc672192200f6821cd22986233d0ee0ac51e43d1dd7e363"},
	}
	testFileHashes = [][3]string{
		// alg, expected (but maybe keyed) hash, expected salted hash
		{"adler32", "00153577", "1af038ee"},
		{"crc32", "29d06dfc", "0f20b19d"},
		{"crc32castagnoli", "52259dc1", "ca35a7de"},
		{"crc32ieee", "29d06dfc", "0f20b19d"},
		{"crc32koopman", "cef05d42", "96d4d7c7"},
		{"crc64", "50907cedc6f31c28", "a36255a49b0572e3"},
		{"crc64ecma", "ab4e1e3b23ca3cfe", "15a3c4147c4fcd1e"},
		{"crc64iso", "50907cedc6f31c28", "a36255a49b0572e3"},
		{"fnv", "cb9e1c3f", "3ed15768"},
		{"fnv32", "cb9e1c3f", "3ed15768"},
		{"fnv32a", "a0a5e177", "8828f8ce"},
		{"fnv64", "a26cc7b0c76f3b7f", "a8ec7784629c63e8"},
		{"fnv64a", "bf87d8edc3e73d77", "b1c21108a13e2b2e"},
		{"hmac", "e388ca73f0a7d89b2131d7096c46455bdfb46bd1d68831684b037ee32bd380d8", "29243c7833bcc577e6657ae7dd1961bb6e5961309ee7a9b46ac3d2f3eab50daa"},
		{"hmacmd5", "c7b8fa07606d75c6e06863287779733c", "b5b8b6944797aac6229e903c42c38f08"},
		{"hmacsha1", "31cd6b9f0e221a60cd2699dd59ee5d385a2bf83d", "b13f54a25064ca2ad11fb3433ab4069b5be5bf20"},
		{"hmacsha256", "e388ca73f0a7d89b2131d7096c46455bdfb46bd1d68831684b037ee32bd380d8", "29243c7833bcc577e6657ae7dd1961bb6e5961309ee7a9b46ac3d2f3eab50daa"},
		{"hmacsha512", "5fb61ebed4aa2bed3c3b8b2d6d0f29d36d0768f2714485e235dc29afc2c0837a204fbce50a1f0279bd12048415e3531f2189109821ff2af1eb4cd72ee6805aeb", "8cbd7e08f9ad0ae5ed550c10e76aae9f1cbb383b84812c5f5bf232b59022437cec5ed67bcad16fa54eefd014caa40d5fa827dc93754611c0c642f41fa46e91ce"},
		{"md4", "28bfdb75a67610d9491d6def782144d4", "69aaba69af8c3d0481c57d95a6bb66c3"},
		{"md5", "7b8778e95a7f8dd72a0dfec7127cf062", "5c8c72d2225091b334c6ee091aab3229"},
		{"ripemd160", "606c0e3b663bc1be0c7b1f1713ee7de6d00ef063", "5d687c74ae181b05378a79bc06b77e3ea9064718"},
		{"sha1", "945409b7fc1a32e77b0b3dbd8ea89c772c05c62d", "fd456ecb6c7ca9eb31eb057236bd44a66ba97146"},
		{"sha224", "63a70617a1185178105c05353e74725a893a21cfc713c32ca9b50010", "d158550acf62df86b193e3298af5349561f2c4c2445aa78734f610ca"},
		{"sha256", "23ce3c431b01ca2592ecc50d3a87212454a6ca86c2c967386705e91f406a1da3", "ab78f06bb2aaa30498cac277cfdd56d694d34ce18c3d8f403adc4cb1a881120a"},
		{"sha384", "dccd2cf610b60814d4bdc78e03db4aefcebfe25f88e6b358b0bb09f74354c557edeb041f80c34241011d362094dda854", "c373da36a9fd7cb8a802f4b3081854f63cb23e5214df58aa03d5b147890831abd6b781ed9d4f038bc0e9999f2d43a3e6"},
		{"sha512", "be31fb961dc5f7ffcd233a430ffea7f6e9dbdfb81d02cf9ddddaca3164233512aa4c2a0b503ede924c1087ebb8fd90773a99855e29f53d2b4f19a6b326852251", "4ce38c37adea3bb37e429059c244fb582a20cb9a195a029d62535a92c0e10a3fd1a07a67a49c6b17d51e82536981f334a238add7df62e54f864d11f9dcc7f7dd"},
	}
)

func init() {
	flag.Parse()
	key = testKey
}

func TestHashString(t *testing.T) {
	for _, v := range testStringHashes {
		h, err := GetHash(v[0])
		if err != nil {
			t.Error("GetHash alg", v[0], ":", err)
			continue
		}
		normal := HashString(h, testStr)
		h.Reset()
		salted := HashString(h, testSalt+testStr)
		if normal != v[1] {
			t.Error("Alg", v[0], "got hash:", normal, "- expected", v[1])
		}
		if salted != v[2] {
			t.Error("Alg", v[0], "got salted hash:", salted, "- expected", v[2])
		}
	}
}

func TestHashFile(t *testing.T) {
	f, err := ioutil.TempFile("", "picugen-testhashfile")
	if err != nil {
		t.Fatal("Couldn't write test hash file")
	}
	f.WriteString(testFile)
	f.Close()

	fname := f.Name()
	for _, v := range testFileHashes {
		h, err := GetHash(v[0])
		if err != nil {
			t.Error("GetGenerator alg", v[0], ":", err)
			continue
		}

		// Normal
		f, err := os.Open(fname)
		if err != nil {
			t.Fatal("Couldn't open hash file", fname)
		}
		salt = ""
		normal, err := HashFile(h, f)
		if err != nil {
			t.Error("Alg", v[0], "HashFile error (normal):", err)
		}
		h.Reset()
		f.Close()

		// Salted
		f, err = os.Open(fname)
		if err != nil {
			t.Fatal("Couldn't open hash file", fname)
		}
		salt = testSalt
		salted, err := HashFile(h, f)
		if err != nil {
			t.Error("Alg", v[0], "HashFile error (salted):", err)
		}
		f.Close()

		// Result
		if normal != v[1] {
			t.Error("Alg", v[0], "got hash:", normal, "- expected", v[1])
		}
		if salted != v[2] {
			t.Error("Alg", v[0], "got salted hash:", salted, "- expected", v[2])
		}
	}
}
