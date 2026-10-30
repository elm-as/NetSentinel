package detection

import (
	"net/netip"
	"testing"
	"time"

	"github.com/elm-as/NetSentinel/internal/baseline"
	"github.com/elm-as/NetSentinel/internal/packet"
)

func TestEvaluateWindowDetectsScanWithoutPoisoningBaseline(t *testing.T) {
	var history baseline.WelfordState
	for _, sample := range []float64{6, 7, 8, 7, 6, 8} {
		history = baseline.ObserveSample(history, sample)
	}

	scanner := netip.MustParseAddr("192.168.1.200")
	target := netip.MustParseAddr("10.0.0.5")
	now := time.Now().UTC()

	var scanEvents []packet.TCPEvent
	for port := uint16(1); port <= 30; port++ {
		scanEvents = append(scanEvents, packet.TCPEvent{
			ObservedAt: now,
			SourceIP:   scanner,
			DestIP:     target,
			SourcePort: 60000,
			DestPort:   port,
			Flags:      packet.FlagSYN,
		})
	}

	verdict := EvaluateWindow(scanEvents, history, DefaultThresholdPolicy())
	if verdict.Severity != SeverityCritical {
		t.Fatalf("gravité CRITICAL attendue sur balayage + pic Z-score, obtenue %s", verdict.Severity)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Reason != "port_scan_sweep" {
		t.Fatalf("signature port_scan_sweep attendue, obtenue %+v", verdict.Findings)
	}
	if verdict.UpdatedHistory.Count != history.Count {
		t.Fatalf("une fenêtre CRITICAL ne doit pas empoisonner la baseline Welford")
	}
}
