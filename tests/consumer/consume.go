package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	bls "github.com/drand/bls12-381"
	sig "github.com/drand/kyber/sign/bls"
)

type testVector struct {
	Msg          string
	Ciphersuite  string
	G1Compressed []byte
	G2Compressed []byte
	BLSPrivKey   string
	BLSPubKey    []byte
	BLSSigG2     []byte
}

func main() {
	fname := os.Args[1]
	f, err := os.Open(fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var tests []testVector
	if err := json.NewDecoder(f).Decode(&tests); err != nil {
		panic(err)
	}
	for i, tv := range tests {
		g1, err := bls.NewG1().HashToCurve([]byte(tv.Msg), []byte(tv.Ciphersuite))
		if err != nil {
			panic(err)
		}
		g1Buff := bls.NewG1().ToCompressed(g1)
		exp := tv.G1Compressed
		if !bytes.Equal(g1Buff, exp) {
			fmt.Println("test", i, " fails at G1")
		}
		g2, err := bls.NewG2(nil).HashToCurve([]byte(tv.Msg), []byte(tv.Ciphersuite))
		if err != nil {
			panic(err)
		}
		g2Buff := bls.NewG2(nil).ToCompressed(g2)
		exp = tv.G2Compressed
		if !bytes.Equal(g2Buff, exp) {
			fmt.Println("test", i, " fails at G2")
		}

		if tv.BLSPrivKey != "" {
			// SIGNATURE is always happening on bls.Domain
			pairing := bls.NewBLS12381Suite()
			scheme := sig.NewSchemeOnG2(pairing)
			pubKey := pairing.G1().Point()
			if err := pubKey.UnmarshalBinary(tv.BLSPubKey); err != nil {
				panic(err)
			}
			err := scheme.Verify(pubKey, []byte(tv.Msg), tv.BLSSigG2)
			if err != nil {
				fmt.Println("test", i, " fails for signature")
			}
		}
	}
}
