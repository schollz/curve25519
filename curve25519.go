// initial implementation from
// https://github.com/temporary00/ed448
// GNU GENERAL PUBLIC LICENSE 3.0
package curve25519

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	curve25519p "golang.org/x/crypto/curve25519"
)

// Curve25519Params contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of Curve.
// These are the Montgomery params.
type Curve25519Params struct {
	ep *elliptic.CurveParams
}

// A Curve25519 represents the curve25519.
type Curve25519 interface {
	elliptic.Curve
}

// Params returns the parameters for the curve.
func (curve *Curve25519Params) Params() *elliptic.CurveParams {
	return curve.ep
}

// IsOnCurve verifies if a given point in montgomery is valid
// v^2 = u^3 + A*u^2 + u
func (curve *Curve25519Params) IsOnCurve(x, y *big.Int) bool {
	t0 := new(big.Int)
	t1 := new(big.Int)
	t2 := new(big.Int)

	t0.Mul(x, x)
	t0.Mul(t0, curve.ep.B)

	t2.Mul(x, x)
	t2.Mul(t2, x)

	t0.Add(t0, t2)
	t0.Add(t0, x)
	t0.Mod(t0, curve.ep.P)

	t1.Mul(y, y)
	t1.Mod(t1, curve.ep.P)

	return t0.Cmp(t1) == 0
}

func isZero(a *big.Int) bool {
	return a.Sign() == 0
}

func isEqual(x, y *big.Int) bool {
	return isZero(new(big.Int).Sub(x, y))
}

func cMov(x, y *big.Int, b bool) *big.Int {
	z := new(big.Int)

	if b {
		z.Set(y)
	} else {
		z.Set(x)
	}

	return z
}

func sgn0LE(x *big.Int) int {
	return 1 - 2*int(x.Bit(0))
}

// Add adds two points in montgomery
// x3 = ((y2-y1)^2/(x2-x1)^2)-A-x1-x2
// y3 = (2*x1+x2+a)*(y2-y1)/(x2-x1)-b*(y2-y1)3/(x2-x1)3-y1
// See: https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html
func (curve *Curve25519Params) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	t0 := new(big.Int)
	t1 := new(big.Int)
	t2 := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)

	if x1.Sign() == 0 || y1.Sign() == 0 {
		return x2, y2
	}

	if x2.Sign() == 0 || y2.Sign() == 0 {
		return x1, y1
	}

	t0.Sub(y2, y1)
	t1.Sub(x2, x1)
	t1 = new(big.Int).ModInverse(t1, curve.ep.P)
	t2.Mul(t0, t1)

	t0.Mul(t2, t2)
	t0.Mul(t0, new(big.Int).SetInt64(1))
	t0.Sub(t0, curve.ep.B)
	t0.Sub(t0, x1)
	x.Sub(t0, x2)

	t0.Sub(x1, x)
	t0.Mul(t0, t2)
	y.Sub(t0, y1)

	x.Mod(x, curve.ep.P)
	y.Mod(y, curve.ep.P)

	return x, y
}

// Double doubles two points in montgomery
// x3 = b*(3*x12+2*a*x1+1)2/(2*b*y1)2-a-x1-x1
// y3 = (2*x1+x1+a)*(3*x12+2*a*x1+1)/(2*b*y1)-b*(3*x12+2*a*x1+1)3/(2*b*y1)3-y1
// See: https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html
func (curve *Curve25519Params) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x1, y1
	}

	t0 := new(big.Int)
	t1 := new(big.Int)
	t2 := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)

	t0.Mul(new(big.Int).SetInt64(3), x1)
	t1.Mul(new(big.Int).SetInt64(2), curve.ep.B)
	t0.Add(t0, t1)
	t0.Mul(t0, x1)
	t1.Add(t0, new(big.Int).SetInt64(1))

	t0.Mul(new(big.Int).SetInt64(2), new(big.Int).SetInt64(1))
	t0.Mul(t0, y1)
	t0 = new(big.Int).ModInverse(t0, curve.ep.P)
	t2.Mul(t1, t0)

	t0.Mul(t2, t2)
	t0.Mul(t0, new(big.Int).SetInt64(1))
	t0.Sub(t0, curve.ep.B)
	t0.Sub(t0, x1)
	x.Sub(t0, x1)

	t0.Sub(x1, x)
	t0.Mul(t0, t2)
	y.Sub(t0, y1)

	x.Mod(x, curve.ep.P)
	y.Mod(y, curve.ep.P)

	return x, y
}

// ScalarMult returns k*(Bx,By) where k is a number in little-endian form.
func (curve *Curve25519Params) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	var dst [32]byte
	s := [32]byte{}
	uB := [32]byte{}

	b := x1.Bytes()
	copy(s[:], k)
	copy(uB[:], b)

	curve25519p.ScalarMult(&dst, &s, &uB)

	u := new(big.Int).SetBytes(dst[:])
	v := new(big.Int)

	return u, v
}

// ScalarBaseMult returns k*(Bx,By) where k is a number in little-endian form.
func (curve *Curve25519Params) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var dst [32]byte
	s := [32]byte{}

	copy(s[:], k)

	curve25519p.ScalarBaseMult(&dst, &s)

	u := new(big.Int).SetBytes(dst[:])
	v := new(big.Int)

	return u, v
}

var initonce sync.Once
var curve25519 *Curve25519Params

func initAll() {
	initCurve25519()
}

func initCurve25519() {
	// See https://safecurves.cr.yp.to/field.html and https://tools.ietf.org/html/rfc7748#section-4.2
	P, _ := new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	N, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	A, _ := new(big.Int).SetString("486662", 10)
	Gu, _ := new(big.Int).SetString("9", 10)
	Gv, _ := new(big.Int).SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
	curve25519 = &Curve25519Params{&elliptic.CurveParams{Name: "curve-25519",
		P:       P,
		N:       N,
		B:       A,
		Gx:      Gu,
		Gy:      Gv,
		BitSize: 256,
	}}
}

// CurveP25519 returns a Curve which implements curve448
func CurveP25519() Curve25519 {
	initonce.Do(initAll)
	return curve25519
}
