package bls

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type groupBls struct {
	str      string
	newPoint func() kyber.Point
}

func (g *groupBls) String() string {
	return g.str
}

func (g *groupBls) Scalar() kyber.Scalar {
	return NewKyberScalar()
}

func (g *groupBls) ScalarLen() int {
	return g.Scalar().MarshalSize()
}

func (g *groupBls) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *groupBls) Point() kyber.Point {
	return g.newPoint()
}

func (g *groupBls) IsPrimeOrder() bool {
	return true
}

func NewGroupG1() kyber.Group {
	return &groupBls{
		str:      "bls12-381.G1",
		newPoint: func() kyber.Point { return nullKyberG1() },
	}
}

func NewGroupG2() kyber.Group {
	return &groupBls{
		str:      "bls12-381.G2",
		newPoint: func() kyber.Point { return nullKyberG2() },
	}
}

func NewGroupGT() kyber.Group {
	return &groupBls{
		str:      "bls12-381.GT",
		newPoint: func() kyber.Point { return newEmptyGT() },
	}
}

type Suite struct {
}

func NewBLS12381Suite() pairing.Suite {
	return &Suite{}
}

func (s *Suite) G1() kyber.Group {
	return NewGroupG1()
}

func (s *Suite) G2() kyber.Group {
	return NewGroupG2()
}

func (s *Suite) GT() kyber.Group {
	return NewGroupGT()
}

func (s *Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	e := NewBLSPairingEngine()
	gt := s.GT().Point().(*KyberGT)
	points := []PointG1{*p1.(*KyberG1).p}
	twistsPoints := []PointG2{*p2.(*KyberG2).p}
	e.pair(gt.f, points, twistsPoints)
	return gt
}

// New implements the kyber.Encoding interface.
func (s *Suite) New(t reflect.Type) interface{} {
	panic("Suite.Encoding: deprecated in drand")
}

// Read is the default implementation of kyber.Encoding interface Read.
func (s *Suite) Read(r io.Reader, objs ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

// Write is the default implementation of kyber.Encoding interface Write.
func (s *Suite) Write(w io.Writer, objs ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

// Hash returns a newly instantiated sha256 hash function.
func (s *Suite) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newlly instantiated blake2xb XOF function.
func (s *Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (s *Suite) RandomStream() cipher.Stream {
	return random.New()
}