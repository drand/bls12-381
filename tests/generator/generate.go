package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	mrand "math/rand"
	"os"

	bls "github.com/drand/bls12-381"
	"github.com/drand/kyber/group/mod"
	sig "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
)

type toWrite struct {
	Msg          string
	Ciphersuite  string
	G1Compressed []byte
	G2Compressed []byte
	BLSPrivKey   string
	BLSPubKey    []byte
	BLSSigG2     []byte
}
type testVector struct {
	msg    string
	cipher string
}

func main() {
	outputName := "compatibility.dat"
	var vectors []toWrite
	var tvs = []testVector{
		{
			msg:    "",
			cipher: "",
		},
		{
			msg:    "",
			cipher: string(bls.Domain),
		},
		{
			msg:    "1234",
			cipher: string(bls.Domain),
		},
	}
	tvs = fill(tvs)
	for _, tv := range tvs {
		g1, err := bls.NewG1().HashToCurve([]byte(tv.msg), []byte(tv.cipher))
		if err != nil {
			panic(err)
		}
		g1Buff := bls.NewG1().ToCompressed(g1)
		g2, err := bls.NewG2(nil).HashToCurve([]byte(tv.msg), []byte(tv.cipher))
		if err != nil {
			panic(err)
		}
		g2Buff := bls.NewG2(nil).ToCompressed(g2)
		s := toWrite{
			Msg:          tv.msg,
			Ciphersuite:  tv.cipher,
			G1Compressed: g1Buff,
			G2Compressed: g2Buff,
		}

		if bytes.Equal([]byte(tv.cipher), bls.Domain) {
			// SIGNATURE is always happening on bls.Domain
			pairing := bls.NewBLS12381Suite()
			scheme := sig.NewSchemeOnG2(pairing)
			priv, pub := scheme.NewKeyPair(random.New())
			privDecimal := priv.(*mod.Int).V.String()
			pubBuff, _ := pub.MarshalBinary()
			signature, err := scheme.Sign(priv, []byte(tv.msg))
			if err != nil {
				panic(err)
			}
			s.BLSPrivKey = privDecimal
			s.BLSPubKey = pubBuff
			s.BLSSigG2 = signature
		}
		vectors = append(vectors, s)
	}
	f, err := os.Create(outputName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(vectors); err != nil {
		panic(err)
	}
}

func fill(tvs []testVector) []testVector {
	tvs = append(tvs, testVector{
		msg:    randomString(32),
		cipher: string(bls.Domain),
	})
	tvs = append(tvs, testVector{
		msg:    randomString(64),
		cipher: string(bls.Domain),
	})
	for i := 0; i < 100; i++ {
		msgLen := mrand.Intn(2000)
		msg := randomString(msgLen)
		tvs = append(tvs, testVector{
			msg:    msg,
			cipher: string(bls.Domain),
		})
	}
	return tvs
}

func randomString(n int) string {
	out := make([]byte, n)
	io.ReadFull(rand.Reader, out)
	return hex.EncodeToString(out)
}
