// Package baseline fournit des estimateurs statistiques en ligne numériquement stables.
package baseline

import "math"

// WelfordState représente les moments suffisants d'une série observée sans stocker l'historique.
// Immuable par valeur : chaque mise à jour retourne un nouvel état pur.
type WelfordState struct {
	Count int
	Mean  float64
	M2    float64
}

// ObserveSample incorpore une nouvelle mesure selon l'algorithme incrémental de Welford.
// Évite l'annulation catastrophique (catastrophic cancellation) de la formule naïve E[X²] - E[X]².
func ObserveSample(current WelfordState, value float64) WelfordState {
	nextCount := current.Count + 1
	delta := value - current.Mean
	nextMean := current.Mean + delta/float64(nextCount)
	delta2 := value - nextMean

	return WelfordState{
		Count: nextCount,
		Mean:  nextMean,
		M2:    current.M2 + delta*delta2,
	}
}

// SampleStdDev calcule l'écart-type corrigé (Bessel, n-1) de la distribution observée.
// Retourne 0 tant que moins de 2 observations sont disponibles.
func SampleStdDev(state WelfordState) float64 {
	if state.Count < 2 || state.M2 <= 0 {
		return 0
	}
	variance := state.M2 / float64(state.Count-1)
	return math.Sqrt(variance)
}

// ComputeZScore quantifie l'écart standardisé d'une observation par rapport à la baseline.
// En dessous d'un minimum de 5 fenêtres d'étalonnage, le Z-score reste neutre (0) pour éviter
// les fausses alertes au démarrage à froid de la sonde.
func ComputeZScore(state WelfordState, candidate float64) float64 {
	const minCalibrationSamples = 5
	if state.Count < minCalibrationSamples {
		return 0
	}

	stdDev := SampleStdDev(state)
	// Plancher minimal de dispersion pour gérer les régimes stationnaires quasi constants
	// (ex. 2 SYN/s constants suivis soudainement de 150 SYN/s où stdDev serait nul).
	effectiveFloor := math.Max(stdDev, math.Max(1.0, 0.10*math.Abs(state.Mean)))
	return (candidate - state.Mean) / effectiveFloor
}
