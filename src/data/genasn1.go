package main

import (
	// "crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"os"
)

var (
	pkcs1                   asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1}
	ansi_x9_62              asn1.ObjectIdentifier = []int{1, 2, 840, 10045}
	ecdsa_with_sha2         asn1.ObjectIdentifier = append(ansi_x9_62, 4, 3)[:6:6]
	ecPublicKey             asn1.ObjectIdentifier = append(ansi_x9_62, 2, 1)
	ecdsa_with_sha224       asn1.ObjectIdentifier = append(ecdsa_with_sha2, 1)
	ecdsa_with_sha256       asn1.ObjectIdentifier = append(ecdsa_with_sha2, 2)
	ecdsa_with_sha384       asn1.ObjectIdentifier = append(ecdsa_with_sha2, 3)
	ecdsa_with_sha512       asn1.ObjectIdentifier = append(ecdsa_with_sha2, 4)
	p256                    asn1.ObjectIdentifier = []int{1, 2, 840, 10045, 3, 1, 7}
	p224                    asn1.ObjectIdentifier = []int{1, 3, 132, 0, 33}
	p384                    asn1.ObjectIdentifier = []int{1, 3, 132, 0, 34}
	p521                    asn1.ObjectIdentifier = []int{1, 3, 132, 0, 35}
	rsaEncryption           asn1.ObjectIdentifier = append(pkcs1, 1)
	mgf1                    asn1.ObjectIdentifier = append(pkcs1, 8)
	rsassa_pss              asn1.ObjectIdentifier = append(pkcs1, 10)
	sha256WithRSAEncryption asn1.ObjectIdentifier = append(pkcs1, 11)
	sha384WithRSAEncryption asn1.ObjectIdentifier = append(pkcs1, 12)
	sha512WithRSAEncryption asn1.ObjectIdentifier = append(pkcs1, 13)
	nisthash                asn1.ObjectIdentifier = []int{2, 16, 840, 1, 101, 3, 4, 2}
	id_sha256               asn1.ObjectIdentifier = append(nisthash, 1)
	id_sha384               asn1.ObjectIdentifier = append(nisthash, 2)
	id_sha512               asn1.ObjectIdentifier = append(nisthash, 3)
	id_x25519               asn1.ObjectIdentifier = []int{1, 3, 101, 110}
	id_x448                 asn1.ObjectIdentifier = []int{1, 3, 101, 111}
	id_ed25519              asn1.ObjectIdentifier = []int{1, 3, 101, 112}
	id_ed448                asn1.ObjectIdentifier = []int{1, 3, 101, 113}
)

type RsaSsa_Pss_params struct {
	HashAlgorithm    AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenAlgorithm AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength       int64               `asn1:"explicit,tag:2"`
	TrailerField     int64               `asn1:"optional,explicit,tag:3,default:1"`
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters interface{} `asn1:"optional,default:asn1.NullRawValue"`
}

func generateECDSA() {
	mustWrite("alg-ecdsa-sha224.der", mustMarshal(ecdsa_with_sha224))
	mustWrite("alg-ecdsa-sha256.der", mustMarshal(ecdsa_with_sha256))
	mustWrite("alg-ecdsa-sha384.der", mustMarshal(ecdsa_with_sha384))
	mustWrite("alg-ecdsa-sha512.der", mustMarshal(ecdsa_with_sha512))
	mustWrite("alg-x25519.der", mustMarshal(id_x25519))
	mustWrite("alg-ed25519.der", mustMarshal(id_ed25519))
	mustWrite("alg-x448.der", mustMarshal(id_x448))
	mustWrite("alg-ed448.der", mustMarshal(id_ed448))
	writeCurve("alg-ecdsa-p224.der", p224)
	writeCurve("alg-ecdsa-p256.der", p256)
	writeCurve("alg-ecdsa-p384.der", p384)
	writeCurve("alg-ecdsa-p521.der", p521)
}

func writeCurve(name string, algorithm asn1.ObjectIdentifier) {
	mustWrite(name, mustMarshal(ecPublicKey), mustMarshal(algorithm))
}

func main() {
	if cap(ecdsa_with_sha2) != len(ecdsa_with_sha2) {
		panic("bug")
	}
	if cap(pkcs1) != len(pkcs1) {
		panic("bug")
	}
	if cap(nisthash) != len(nisthash) {
		panic("bug")
	}
	generateECDSA()
	generateRsaSsaPrefix()
	mustWrite("alg-rsa-encryption.der", mustMarshal(rsaEncryption), []byte{5, 0})
	mustWrite("alg-rsa-pkcs1-sha256.der", mustMarshal(sha256WithRSAEncryption), []byte{5, 0})
	mustWrite("alg-rsa-pkcs1-sha384.der", mustMarshal(sha384WithRSAEncryption), []byte{5, 0})
	mustWrite("alg-rsa-pkcs1-sha512.der", mustMarshal(sha512WithRSAEncryption), []byte{5, 0})
	generateRsaSsaPss("alg-rsa-pss-sha256", id_sha256, 32)
	generateRsaSsaPss("alg-rsa-pss-sha384", id_sha384, 48)
	generateRsaSsaPss("alg-rsa-pss-sha512", id_sha512, 64)
}

func generateRsaSsaPss(filename string, oid asn1.ObjectIdentifier, length int64) {
	generateRsaSsaPssVersion(filename+"-v0.der", oid, length, false, false)
	generateRsaSsaPssVersion(filename+"-v1.der", oid, length, false, true)
	generateRsaSsaPssVersion(filename+"-v2.der", oid, length, true, false)
	generateRsaSsaPssVersion(filename+"-v3.der", oid, length, true, true)
}

func getVersion(generate bool) (result asn1.RawValue) {
	if generate {
		result = asn1.NullRawValue
	}
	return
}

func mustMarshal(datum interface{}) []byte {
	marshalled, err := asn1.Marshal(datum)
	if nil != err {
		panic(err)
	}
	return marshalled
}

var rsaSsaPss []byte = mustMarshal(rsassa_pss)

func mustWrite(filename string, bytes ...[]byte) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal("could not open")
	}
	for _, data := range bytes {
		if length, err := f.Write(data); nil != err || length != len(data) {
			log.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		log.Fatal(err)
	}
}

func generateRsaSsaPrefix() {
	mustWrite("alg-rsa-pss.der", rsaSsaPss)
}

func generateRsaSsaPssVersion(filename string, oid asn1.ObjectIdentifier, length int64, useFirstNull, useSecondNull bool) {
	mgf1Params := AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: getVersion(useSecondNull),
	}
	params := RsaSsa_Pss_params{
		HashAlgorithm: AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: getVersion(useFirstNull),
		},
		MaskGenAlgorithm: AlgorithmIdentifier{
			Algorithm:  mgf1,
			Parameters: mgf1Params,
		},
		SaltLength:   length,
		TrailerField: 1,
	}
	marshalled := mustMarshal(params)
	if len(marshalled) < 30 {
		panic("bug")
	}
	mustWrite(filename, marshalled)
}
