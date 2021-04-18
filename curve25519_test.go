package curve25519

import (
	"math/big"
	"testing"
)

func TestDouble(t *testing.T) {
	curve := CurveP25519()
	x1, _ := new(big.Int).SetString("9", 10)
	y1, _ := new(big.Int).SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
	x, y := curve.Double(x1, y1)
	u, _ := new(big.Int).SetString("6784692728748995825599862402855483522016546426567910438357042338075027826575", 10)
	v, _ := new(big.Int).SetString("14982863109320699114866362806305859444453206692004135551371801829915686450358", 10)
	if x.Cmp(u) != 0 {
		t.Errorf("curve.Double() gotX = %v, want %v", x, u)
	}
	if y.Cmp(v) != 0 {
		t.Errorf("curve.Double() gotY = %v, want %v", y, v)
	}
	x, y = curve.Double(x, y)
	u, _ = new(big.Int).SetString("12318642006867402687195826566147291859634823582672295191656499276835526033145", 10)
	v, _ = new(big.Int).SetString("9343467693237486709905252998911952863134805995110526737200728195882424275543", 10)
	if x.Cmp(u) != 0 {
		t.Errorf("curve.Double() gotX = %v, want %v", x, u)
	}
	if y.Cmp(v) != 0 {
		t.Errorf("curve.Double() gotY = %v, want %v", y, v)
	}
}
