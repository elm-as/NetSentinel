package baseline

import (
	"math"
	"testing"
)

func TestWelfordMeanAndStdDev(t *testing.T) {
	samples := []float64{10, 12, 23, 23, 16, 23, 21, 16}
	var state WelfordState
	for _, x := range samples {
		state = ObserveSample(state, x)
	}

	if math.Abs(state.Mean-18.0) > 1e-9 {
		t.Fatalf("moyenne attendue 18.0, obtenue %.6f", state.Mean)
	}
	// Somme des carrés des écarts autour de 18 : 64+36+25+25+4+25+9+4 = 192 ; s² = 192/7
	expectedStd := math.Sqrt(192.0 / 7.0)
	if math.Abs(SampleStdDev(state)-expectedStd) > 1e-6 {
		t.Fatalf("écart-type attendu %.6f, obtenu %.6f", expectedStd, SampleStdDev(state))
	}
}

func TestComputeZScoreColdStartAndSpike(t *testing.T) {
	var state WelfordState
	for _, x := range []float64{8, 9, 8} {
		state = ObserveSample(state, x)
	}
	if z := ComputeZScore(state, 120); z != 0 {
		t.Fatalf("le garde-fou de démarrage à froid doit retourner 0 avant 5 mesures, obtenu %.2f", z)
	}

	state = ObserveSample(state, 10)
	state = ObserveSample(state, 9)
	if z := ComputeZScore(state, 90); z < 10.0 {
		t.Fatalf("un pic massif après étalonnage doit produire un Z-score élevé, obtenu %.2f", z)
	}
}
