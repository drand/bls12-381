package bls

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func mapG2PairedV18(msg []byte, ciphersuite []byte) *PointG2 {
	padded := make([]byte, len(msg)+1)
	copy(padded, msg)
	msg = padded
	//fmt.Println("input to hkdf.extract: msg: ", msg, " -- cipher: ", ciphersuite)
	msg_hash := hkdf.Extract(sha256.New, msg, ciphersuite)
	//fmt.Println("msg_hash: ", msg_hash)
	var fe2s []*fe2
	for ctrI := 0; ctrI < 2; ctrI++ {
		var fes []*fe
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
			// XXX TO CHANGE
			fes = append(fes, new(fe))
		}
		// use the two Fq to create one Fq2
		// XXX TO CHANGE
		fe2s = append(fe2s, new(fe2)) // FromFq(...)
	}
	return mapFq2sToG2(fe2s[0], fe2s[1])
}

func mapG1PairedV18(msg []byte, ciphersuite []byte) *PointG1 {
	msg_hash := hkdf.Extract(sha256.New, msg, ciphersuite)
	var fes []*fe
	for ctrI := 0; ctrI < 2; ctrI++ {
		var ctr = byte(ctrI)
		var idx = byte(1)
		info := []byte{72, 50, 67, ctr, idx}

		out := make([]byte, 64)
		h := hkdf.Expand(sha256.New, msg_hash, info)
		if _, err := io.ReadFull(h, out); err != nil {
			panic(err)
		}
		fmt.Println("counter", ctr, "index", idx, "out: ", out)
		// XXX TO CHANGE
		fes = append(fes, new(fe))
	}
	return mapFqsToG1(fes[0], fes[1])
}

//// PAIRING PLUS PART

func mapG2PairingPlusV19Sha256(msg []byte, ciphersuite []byte) *PointG2 {
	expanded := expandMessageSha256(msg, ciphersuite)
	len_per_elm := 128
	var fe2s []*fe2
	for i := 0; i < 2; i++ {
		bytesToConvert := expanded[i*len_per_elm : (i+1)*len_per_elm]
		//fmt.Println(" convert: i ", i, " bytes ->", bytesToConvert)
		fq_1 := bytesToConvert[:64]
		fq_2 := bytesToConvert[64:]
		fmt.Println("ctr:", i, " fq_1", fq_1, "fq_2", fq_2)
		// XXX TO CHANGE: form fe2 from fq_1 and fq_2
		fe2s = append(fe2s, new(fe2))
	}
	return mapFq2sToG2(fe2s[0], fe2s[1])
}

func mapG1PairingPlusV19Sha256(msg []byte, ciphersuite []byte) *PointG1 {
	expanded := expandMessageSha256(msg, ciphersuite)
	len_per_elm := 128
	var fes []*fe
	for i := 0; i < 2; i++ {
		bytesToConvert := expanded[i*len_per_elm : (i+1)*len_per_elm]
		//fmt.Println(" convert: i ", i, " bytes ->", bytesToConvert)
		fq_1 := bytesToConvert[:32]
		fq_2 := bytesToConvert[32:]
		fmt.Println("fq_1", fq_1, "fq_2", fq_2)
		// XXX TO CHANGE: form fe2 from fq_1 and fq_2
		fes = append(fes, new(fe))
	}
	return mapFqsToG1(fes[0], fes[1])
}

func expandMessageSha256(msg, domain []byte) []byte {
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

///// COMMON PART

func mapFq2sToG2(u1, u2 *fe2) *PointG2 {
	g := NewG2(nil)
	fp2 := g.f
	one := fp2.one()
	x1, y1 := fp2.swuMap(u1)
	q1 := &PointG2{*x1, *y1, *one}
	x2, y2 := fp2.swuMap(u2)
	q2 := &PointG2{*x2, *y2, *one}
	qaccRaw := g.New()
	g.Add(qaccRaw, q1, q2)
	g.Affine(qaccRaw)
	xacc := qaccRaw[0]
	yacc := qaccRaw[1]

	// apply isogeny map to accumulated
	fp2.isogenyMap(&xacc, &yacc)
	r1 := &PointG2{xacc, yacc, *one}

	// clear cofactor
	g.MulScalar(r1, r1, cofactorEFFG2)
	g.Affine(r1)
	return r1
}

func mapFqsToG1(u1, u2 *fe) *PointG1 {
	g := NewG1()
	one := one()
	x1, y1 := swuMap(u1)
	q1 := &PointG1{*x1, *y1, *one}
	x2, y2 := swuMap(u2)
	q2 := &PointG1{*x2, *y2, *one}
	qaccRaw := g.New()
	g.Add(qaccRaw, q1, q2)
	g.Affine(qaccRaw)
	xacc := qaccRaw[0]
	yacc := qaccRaw[1]

	// apply isogeny map to accumulated
	isogenyMap(&xacc, &yacc)
	r1 := &PointG1{xacc, yacc, *one}

	// clear cofactor
	g.MulScalar(r1, r1, cofactorEFFG1)
	g.Affine(r1)
	return r1

}
