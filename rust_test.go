package bls

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func hashRust(g2 *G2, msg []byte, ciphersuite []byte) *PointG2 {
	msg_hash := hkdf.Extract(sha256.New, msg, ciphersuite)
	for ctrI := 0; ctrI < 2; ctrI++ {
		// fq2 has two Fq goes from idx 1->2
		for i := 1; i < 3; i++ {
			var ctr = byte(ctrI)
			var idx = byte(i)
			info := []byte{72, 50, 67, ctr, idx}

			out := make([]byte, 64)
			h := hkdf.Expand(sha256.New, msg_hash, info)
			if _, err := io.ReadFull(h, out); err != nil {
				panic(err)
			}
			fmt.Println("counter", ctr, "index", idx, "out: ", out)
			// use out to map to Fq using following:
			// fn from_okm(okm: &GenericArray<u8, U64>) -> Fq {
			// let mut repr = FqRepr::default();
			// repr.read_be(Cursor::new([0; 16]).chain(Cursor::new(&okm[..32])))
			// 	.unwrap();
			// let mut elm = Fq::from_repr(repr).unwrap();
			// elm.mul_assign(&F_2_256);

			// repr.read_be(Cursor::new([0; 16]).chain(Cursor::new(&okm[32..])))
			// 	.unwrap();
			// let elm2 = Fq::from_repr(repr).unwrap();
			// elm.add_assign(&elm2);
			// elm
		}
		// use the two Fq to create one Fq2
	}
	// use the two Fq2 to create G2
	return nil
}

func expandMessage(msg, domain []byte, length int) []byte {
	// b_0
	h := sha256.New()
	h.Write(make([]byte, 64))
	h.Write(msg)
	h.Write([]byte{byte(length >> 8), byte(length), 0})
	h.Write(domain)
	h.Write([]byte{byte(len(domain))})
	b0 := h.Sum(nil)
	// b_1
	h = sha256.New()
	h.Write(b0)
	h.Write([]byte{byte(1)})
	h.Write(domain)
	h.Write([]byte{byte(len(domain))})
	bvals := h.Sum(nil)
	fmt.Println("b0: ", b0)
	fmt.Println("bvals: ", bvals)

	// ell = 8
	for i := 1; i < 8; i++ {

	}
	return nil
}

func computeFq(msg, cipher []byte, count int) []*fe {
	return nil
}

func hashPlus(g2 *G2, msg []byte, cipher []byte) *PointG2 {

	return nil
}

func TestPairingPlus(t *testing.T) {
	var msg = []byte{1}
	var ciphersuite = []byte{10}
	len_bytes := 256
	expandMessage(msg, ciphersuite, len_bytes)
	//fmt.Printf("expanded message (len %d): %v\n", len(expanded), expanded)
}
func TestCurrentPaired(t *testing.T) {
	var msg = []byte{1, 0} // 0 padded
	var ciphersuite = []byte{10}
	hashRust(NewG2(nil), msg, ciphersuite)
}
