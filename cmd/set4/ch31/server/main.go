package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/ellemouton/cryptopals/set2"
	"github.com/ellemouton/cryptopals/set4"
)

var key []byte

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	// Generate a key
	key = set2.GenAESKey()

	http.HandleFunc("/test", verifySig)
	if err := http.ListenAndServe("127.0.0.1:9000", nil); err != nil {
		log.Fatal(err)
	}
}

func verifySig(w http.ResponseWriter, r *http.Request) {
	files, ok := r.URL.Query()["file"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "file not provided")
		return
	}

	sigs, ok := r.URL.Query()["signature"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "signature not provided")
		return
	}

	file, sig := files[0], sigs[0]

	if file == "" || sig == "" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "file or signature not provided")
		return
	}

	expected, err := set4.HMACSHA1(key, []byte(file))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}

	fmt.Fprintln(w, hex.EncodeToString(expected))

	sigB, err := hex.DecodeString(sig)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}

	if !set4.InsecureCompare(expected, sigB, time.Millisecond*50) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "invalid sig")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "success!")
}
