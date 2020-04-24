package bls

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

/////// PAIRED
// Following implements both the mapping to Fq from here
// https://github.com/filecoin-project/pairing/blob/master/src/hash_to_field.rs#L70
// and then creating the point here
// https://github.com/filecoin-project/pairing/blob/master/src/hash_to_curve.rs#L24
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
	// 	let mut tmp = PtT::osswu_map(&u[0]);
	//  tmp.add_assign(&PtT::osswu_map(&u[1]));
	// 	tmp.isogeny_map();
	//  tmp.clear_h();

	return nil
}

//////   PAIRING_PLUS
// following method implements
// https://github.com/algorand/pairing-plus/blob/master/src/hash_to_field.rs#L18
func expandMessage(msg, domain []byte) []byte {
	len_in_bytes := 256
	length := len_in_bytes // just easier
	// b_0
	h := sha256.New()
	// XXX Why do they hash a 64 byte slice empty !?
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
	//fmt.Println("b0: ", b0)
	//fmt.Println("bvals: ", bvals)

	// ell = 8
	b_in_bytes := 32
	for i := 1; i < 8; i++ {
		tmp := make([]byte, 32)
		//fmt.Println("(i-1) ", i-1, " i ", i, " b_bytes", b_in_bytes)
		toZip := bvals[(i-1)*b_in_bytes : i*b_in_bytes]
		if len(toZip) != len(b0) {
			panic("should check")
		}
		for j := 0; j < len(toZip); j++ {
			tmp[j] = b0[j] ^ toZip[j]
		}
		//fmt.Println("\ttmp i", i, " --> ", tmp)
		h = sha256.New()
		h.Write(tmp)
		h.Write([]byte{byte(i + 1)})
		h.Write(domain)
		h.Write([]byte{byte(len(domain))})
		bvals = append(bvals, h.Sum(nil)...)
		//fmt.Println("\t bvals i ", i, " -> ", bvals)
	}
	return bvals[:len_in_bytes]
}

// following implements
// https://github.com/algorand/pairing-plus/blob/master/src/hash_to_curve.rs#L30
// with hardcoded value for sha256 and the xmd mechanism
// In rust it corresponds to using:
// let g2 = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(vec![1],vec![10]);
// - taken from the bls library from the ref
// https://github.com/algorand/bls_sigs_ref/blob/master/rust-impl/src/signature.rs#L413
func computeFq(msg, domain []byte, count int) {
	expanded := expandMessage(msg, domain)
	len_per_elm := 128
	//fq2List := make([]fq2, 2)
	for i := 0; i < count; i++ {
		bytesToConvert := expanded[i*len_per_elm : (i+1)*len_per_elm]
		//fmt.Println(" convert: i ", i, " bytes ->", bytesToConvert)
		fq_1 := bytesToConvert[:64]
		fq_2 := bytesToConvert[64:]
		fmt.Println("fq_1", fq_1, "fq_2", fq_2)
		// convert both into Fq and then into Fq2
		// using same method as before
		//
		// let mut repr = FqRepr::default();
		// repr.read_be(Cursor::new([0; 16]).chain(Cursor::new(&okm[..32])))
		//     .unwrap();
		// let mut elm = Fq::from_repr(repr).unwrap();
		// elm.mul_assign(&F_2_256);

		// repr.read_be(Cursor::new([0; 16]).chain(Cursor::new(&okm[32..])))
		//     .unwrap();
		// let elm2 = Fq::from_repr(repr).unwrap();
		// elm.add_assign(&elm2);
		// elm
	}
	// use the two Fq2 created above with the osswu map
	// u is an array of two Fq2
	// 	let mut tmp = PtT::osswu_map(&u[0]);
	//  tmp.add_assign(&PtT::osswu_map(&u[1]));
	// 	tmp.isogeny_map();
	//  tmp.clear_h();
}

func hashPlus(g2 *G2, msg []byte, cipher []byte) *PointG2 {

	return nil
}

func TestPairingPlus(t *testing.T) {
	var msg = []byte{1}
	var ciphersuite = []byte{10}
	//var expanded = expandMessage(msg, ciphersuite)
	//fmt.Printf("expanded message (len %d): %v\n", len(expanded), expanded)
	computeFq(msg, ciphersuite, 2)
}
func TestCurrentPaired(t *testing.T) {
	var msg = []byte{1, 0} // 0 padded
	var ciphersuite = []byte{10}
	hashRust(NewG2(nil), msg, ciphersuite)
}
