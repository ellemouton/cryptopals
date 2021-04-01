package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/ellemouton/cryptopals/set2"
)

func main() {

	admin := set2.PKCS7Pad([]byte("admin"), 16)

	fluff := []byte{}
	for len(fluff) < 16-len([]byte("email=")) {
		fluff = append(fluff, []byte("A")[0])
	}
	fluff = append(fluff, admin...)

	enc, err := EncryptProfile(string(fluff))
	if err != nil {
		log.Fatal(err)
	}

	adminCT := enc[16:32]
	fmt.Println(adminCT)

	fmt.Println(len([]byte("email=")))
	fmt.Println(len([]byte("&uid=10&role=")))

	email := []byte{}
	for len(email) < 32-len([]byte("email="))-len([]byte("&uid=10&role=")) {
		email = append(email, []byte("A")[0])
	}

	fmt.Println(email)
	fmt.Println(profile_for(string(email)))

	profPRE, err := EncryptProfile(string(email))
	if err != nil {
		log.Fatal(err)
	}

	copy(profPRE[32:48], adminCT[:])

	dec, err := set2.DecryptECBFixedKey(profPRE)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(dec))
}

type info map[string]string

func marshal(input string) (info, error) {
	parts := strings.Split(input, "&")

	res := make(info)

	for _, p := range parts {
		pair := strings.Split(p, "=")
		if len(pair) != 2 {
			return nil, errors.New("must be a key-value pair separated by an '='")
		}

		res[pair[0]] = pair[1]
	}

	return res, nil
}

func unmarshal(input info) string {
	res, sep := "", ""

	for k, v := range input {
		res += sep + k + "=" + v
		sep = "&"
	}

	return res
}

func EncryptProfile(email string) ([]byte, error) {
	prf, err := profile_for(email)
	if err != nil {
		return nil, err
	}

	return set2.EncryptECBFixedKey([]byte(prf))
}

func profile_for(email string) (string, error) {
	if strings.ContainsAny(email, "&=") {
		return "", errors.New("email cant contain '&' or '='")
	}

	profile := "email=" + email + "&uid=10&role=user"

	return profile, nil
}
