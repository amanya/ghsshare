package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/ianmcmahon/encoding_ssh"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	githubApiEndpoint = flag.String("github-api-endpoint", "https://api.github.com", "GitHub's API endpoint (for using with enterprise setups")
	privateKeyFile    = flag.String("private-key", os.Getenv("HOME")+"/.ssh/id_rsa", "The private key file used to decrypt")
	decrypt           = flag.Bool("decrypt", false, "Decrypt the input instead of encrypting")
	username          = ""
)

type Key struct {
	Id  int
	Key string
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: ghsshare [flags] [username]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func perror(err error) {
	if err != nil {
		log.Fatalf("%s\n", err)
		os.Exit(1)
	}
}

func getGithubKeys() string {
	url := *githubApiEndpoint + "/users/" + username + "/keys"
	res, err := http.Get(url)
	perror(err)
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	perror(err)
	var keys []Key
	json.Unmarshal(body, &keys)
	if len(keys) > 1 {
		log.Printf("user with %d keys, taking the first one", len(keys))
	}
	return keys[0].Key
}

func getPrivateKey() *rsa.PrivateKey {
	pemData, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatalf("read private key: %s\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("read private key: %s\n", err)
		os.Exit(1)
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
		os.Exit(1)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
		os.Exit(1)
	}

	return priv
}

func getPublicKey(key string) *rsa.PublicKey {
	pub, err := ssh.DecodePublicKey(key)
	if err != nil {
		log.Fatalf("bad public key: %s", err)
		os.Exit(1)
	}

	return pub.(*rsa.PublicKey)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	in, _ := ioutil.ReadAll(os.Stdin)

	if *decrypt == false {
		if flag.NArg() < 1 {
			usage()
		}

		username = flag.Arg(0)

		pub := getPublicKey(getGithubKeys())
		ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, []byte(in), nil)
		if err != nil {
			log.Fatalf("error encrypting: %s", err)
			os.Exit(1)
		}
		os.Stdout.Write([]byte(base64.URLEncoding.EncodeToString(ciphertext)))
	} else {
		priv := getPrivateKey()
		ciphertext, err := base64.URLEncoding.DecodeString(string(in))
		if err != nil {
			log.Fatalf("error decoding input: %s", err)
			os.Exit(1)
		}
		out, err := rsa.DecryptOAEP(sha1.New(), nil, priv, ciphertext, nil)
		if err != nil {
			log.Fatalf("error decrypting: %s", err)
			os.Exit(1)
		}
		os.Stdout.Write([]byte(out))
	}
}
