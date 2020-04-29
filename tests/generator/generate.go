package main

import (
	"encoding/json"
	"os"

	bls "github.com/drand/bls12-381"
)

type toWrite struct {
	Msg          string
	Ciphersuite  string
	G1Compressed []byte
	G2Compressed []byte
}

func main() {
	outputName := "compatibility.dat"
	type testVector struct {
		msg    string
		cipher string
	}

	var vectors []toWrite
	for _, tv := range []testVector{
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
		{
			msg:    "abaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			cipher: string(bls.Domain),
		},
	} {
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
