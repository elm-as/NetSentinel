// Package detection évalue les anomalies comportementales TCP par fenêtre temporelle.
package detection

import (
	"net/netip"

	"github.com/elm-as/NetSentinel/internal/baseline"
	"github.com/elm-as/NetSentinel/internal/packet"
)

// Severity classe le niveau de criticité opérationnelle d'une alerte réseau.
type Severity string

const (
	SeverityNominal  Severity = "NOMINAL"
	SeveritySuspect  Severity = "SUSPECT"
	SeverityCritical Severity = "CRITICAL"
)

// ThresholdPolicy regroupe les seuils statistiques configurables du moteur de détection.
type ThresholdPolicy struct {
	PortScanDistinctPorts int
	SynFloodMinPackets    int
	SynAckImbalanceRatio  float64
	AnomalyZScoreCutoff   float64
}

// DefaultThresholdPolicy retourne des seuils prudents calibrés pour un segment LAN/serveur.
func DefaultThresholdPolicy() ThresholdPolicy {
	return ThresholdPolicy{
		PortScanDistinctPorts: 15,
		SynFloodMinPackets:    40,
		SynAckImbalanceRatio:  4.0,
		AnomalyZScoreCutoff:   3.0,
	}
}

// SourceFinding décrit une source IP présentant une signature de scan ou d'inondation SYN.
type SourceFinding struct {
	SourceIP      netip.Addr
	Reason        string
	DistinctPorts int
	SynOnlyCount  int
	RstCount      int
}

// WindowVerdict résume le diagnostic immuable d'une fenêtre de trafic TCP.
type WindowVerdict struct {
	TotalPackets   int
	TotalSynOnly   int
	SynRateZScore  float64
	Severity       Severity
	Findings       []SourceFinding
	UpdatedHistory baseline.WelfordState
}

type hostCounter struct {
	ports    map[uint16]struct{}
	synOnly  int
	synAck   int
	rstCount int
}

// EvaluateWindow analyse purement un lot d'événements TCP face à l'historique statistique.
// L'état historique n'est mis à jour avec la fenêtre courante que si celle-ci n'est pas
// critique, afin d'éviter l'empoisonnement de la baseline pendant une attaque active.
func EvaluateWindow(
	events []packet.TCPEvent,
	history baseline.WelfordState,
	policy ThresholdPolicy,
) WindowVerdict {
	perSource := aggregateBySource(events)
	totalSyn := 0
	var findings []SourceFinding

	for srcIP, stats := range perSource {
		totalSyn += stats.synOnly
		if finding, flagged := inspectHostBehavior(srcIP, stats, policy); flagged {
			findings = append(findings, finding)
		}
	}

	zScore := baseline.ComputeZScore(history, float64(totalSyn))
	severity := classifySeverity(findings, zScore, policy.AnomalyZScoreCutoff)

	nextHistory := history
	if severity != SeverityCritical {
		nextHistory = baseline.ObserveSample(history, float64(totalSyn))
	}

	return WindowVerdict{
		TotalPackets:   len(events),
		TotalSynOnly:   totalSyn,
		SynRateZScore:  zScore,
		Severity:       severity,
		Findings:       findings,
		UpdatedHistory: nextHistory,
	}
}

func aggregateBySource(events []packet.TCPEvent) map[netip.Addr]*hostCounter {
	hosts := make(map[netip.Addr]*hostCounter)
	for _, ev := range events {
		entry, exists := hosts[ev.SourceIP]
		if !exists {
			entry = &hostCounter{ports: make(map[uint16]struct{})}
			hosts[ev.SourceIP] = entry
		}
		entry.ports[ev.DestPort] = struct{}{}
		if ev.Flags.IsSYNOnly() {
			entry.synOnly++
		}
		if ev.Flags.IsSYNACK() {
			entry.synAck++
		}
		if ev.Flags.HasRST() {
			entry.rstCount++
		}
	}
	return hosts
}

func inspectHostBehavior(
	srcIP netip.Addr,
	stats *hostCounter,
	policy ThresholdPolicy,
) (SourceFinding, bool) {
	distinctPorts := len(stats.ports)
	if distinctPorts >= policy.PortScanDistinctPorts {
		return SourceFinding{
			SourceIP:      srcIP,
			Reason:        "port_scan_sweep",
			DistinctPorts: distinctPorts,
			SynOnlyCount:  stats.synOnly,
			RstCount:      stats.rstCount,
		}, true
	}

	ratio := float64(stats.synOnly) / float64(max(1, stats.synAck))
	if stats.synOnly >= policy.SynFloodMinPackets && ratio >= policy.SynAckImbalanceRatio {
		return SourceFinding{
			SourceIP:      srcIP,
			Reason:        "syn_flood_burst",
			DistinctPorts: distinctPorts,
			SynOnlyCount:  stats.synOnly,
			RstCount:      stats.rstCount,
		}, true
	}

	return SourceFinding{}, false
}

func classifySeverity(findings []SourceFinding, zScore float64, zCutoff float64) Severity {
	if len(findings) > 0 && zScore >= zCutoff {
		return SeverityCritical
	}
	if len(findings) > 0 || zScore >= zCutoff {
		return SeveritySuspect
	}
	return SeverityNominal
}
