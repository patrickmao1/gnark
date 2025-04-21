package sw_bls12381

import (
	"fmt"
	"github.com/consensys/gnark/std/math/uints"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// Test clear cofactor
type ClearCofactorCircuit struct {
	Point G1Affine
	Res   G1Affine
}

func (circuit *ClearCofactorCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	clearedPoint := g.ClearCofactor(&circuit.Point)
	g.AssertIsEqual(clearedPoint, &circuit.Res)
	return nil
}

func TestClearCofactor(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g1, _ := bls12381.Generators()
	var g2 bls12381.G1Affine
	g2.ClearCofactor(&g1)
	witness := ClearCofactorCircuit{
		Point: NewG1Affine(g1),
		Res:   NewG1Affine(g2),
	}
	err := test.IsSolved(&ClearCofactorCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Test MapToCurve
type MapToCurveCircuit struct {
	U   emulated.Element[BaseField]
	Res G1Affine
}

func (circuit *MapToCurveCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}

	r, err := g.MapToCurve1(&circuit.U)
	if err != nil {
		return err
	}

	g.AssertIsEqual(r, &circuit.Res)

	return nil
}

func TestMapToCurve(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToCurve1(&a)

	witness := MapToCurveCircuit{
		U:   emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		Res: NewG1Affine(g),
	}
	err := test.IsSolved(&MapToCurveCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Test Map to G1
type MapToG1Circuit struct {
	A emulated.Element[BaseField]
	R G1Affine
}

func (circuit *MapToG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	res, err := g.MapToG1(&circuit.A)
	if err != nil {
		return err
	}

	g.AssertIsEqual(res, &circuit.R)

	return nil
}

func TestMapToG1(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToG1(a)

	witness := MapToG1Circuit{
		A: emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		R: NewG1Affine(g),
	}
	err := test.IsSolved(&MapToG1Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsogenyG1Circuit struct {
	In  G1Affine
	Res G1Affine
}

func (c *IsogenyG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	res := g.isogeny(&c.In)
	g.AssertIsEqual(res, &c.Res)
	return nil
}

func TestIsogenyG1(t *testing.T) {
	assert := test.NewAssert(t)
	in, _ := randomG1G2Affines()
	var res bls12381.G1Affine
	res.Set(&in)
	hash_to_curve.G1Isogeny(&res.X, &res.Y)
	witness := IsogenyG1Circuit{
		In:  NewG1Affine(in),
		Res: NewG1Affine(res),
	}
	err := test.IsSolved(&IsogenyG1Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type hashToG1Circuit struct {
	Msg []byte
	Dst []byte
	Res G1Affine
}

func (c *hashToG1Circuit) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return err
	}
	res, e := g1.HashToG1(uints.NewU8Array(c.Msg), c.Dst)
	if e != nil {
		return e
	}

	g1.AssertIsEqual(res, &c.Res)
	return nil
}

func TestHashToG1TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	dst := getDst()

	for _, msg := range getMsgs() {

		expected, _ := bls12381.HashToG1([]uint8(msg), dst)
		wrappedRes := NewG1Affine(expected)

		circuit := hashToG1Circuit{
			Msg: []uint8(msg),
			Dst: dst,
			Res: wrappedRes,
		}
		witness := hashToG1Circuit{
			Msg: []uint8(msg),
			Dst: dst,
			Res: wrappedRes,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
