package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/elm-as/NetSentinel/internal/baseline"
	"github.com/elm-as/NetSentinel/internal/detection"
	"github.com/elm-as/NetSentinel/internal/packet"
)

type cliOptions struct {
	pcapPath  string
	windowSec int
	runDemo   bool
}

func main() {
	opts := parseFlags()
	if !opts.runDemo && opts.pcapPath == "" {
		fmt.Fprintln(os.Stderr, "Usage : netsentinel --demo  OU  netsentinel --pcap capture.pcap [--window 5]")
		os.Exit(2)
	}

	if opts.runDemo {
		runSyntheticBenchmark()
		return
	}

	if err := analyzePCAPFile(opts.pcapPath, time.Duration(opts.windowSec)*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() cliOptions {
	pcapPath := flag.String("pcap", "", "Chemin vers un fichier .pcap standard (Ethernet/IPv4)")
	windowSec := flag.Int("window", 5, "Durée d'une fenêtre d'agrégation en secondes")
	runDemo := flag.Bool("demo", false, "Exécute un scénario de référence (trafic sain + scan + SYN flood)")
	flag.Parse()

	return cliOptions{
		pcapPath:  *pcapPath,
		windowSec: max(1, *windowSec),
		runDemo:   *runDemo,
	}
}

func analyzePCAPFile(path string, windowSpan time.Duration) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	events, err := packet.ReadPCAPTCPStream(file)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Println("Aucun segment TCP IPv4 détecté dans la capture.")
		return nil
	}

	windows := partitionByWindow(events, windowSpan)
	printTelemetryTable(windows, detection.DefaultThresholdPolicy())
	return nil
}

func partitionByWindow(events []packet.TCPEvent, span time.Duration) [][]packet.TCPEvent {
	var buckets [][]packet.TCPEvent
	windowEnd := events[0].ObservedAt.Add(span)
	var current []packet.TCPEvent

	for _, ev := range events {
		if ev.ObservedAt.Before(windowEnd) {
			current = append(current, ev)
			continue
		}
		buckets = append(buckets, current)
		current = []packet.TCPEvent{ev}
		windowEnd = ev.ObservedAt.Add(span)
	}
	if len(current) > 0 {
		buckets = append(buckets, current)
	}
	return buckets
}

func runSyntheticBenchmark() {
	fmt.Println("=== NetSentinel v0.1 — Simulation de télémétrie passive TCP/IP ===")
	baseTime := time.Date(2026, 10, 30, 18, 0, 0, 0, time.UTC)
	var windows [][]packet.TCPEvent

	// 6 fenêtres d'étalonnage nominales (trafic web HTTPS régulier)
	for w := range 6 {
		windows = append(windows, buildNormalWindow(baseTime.Add(time.Duration(w)*5*time.Second), 8+(w%3)))
	}
	// Fenêtre 7 : balayage rapide de 28 ports distincts depuis un hôte interne suspect
	windows = append(windows, buildPortScanWindow(baseTime.Add(30*time.Second), 28))
	// Fenêtre 8 : rafale SYN flood asymétrique (95 SYN sans ACK)
	windows = append(windows, buildSynFloodWindow(baseTime.Add(35*time.Second), 95))

	printTelemetryTable(windows, detection.DefaultThresholdPolicy())
}

func printTelemetryTable(windows [][]packet.TCPEvent, policy detection.ThresholdPolicy) {
	fmt.Printf("%-8s  %8s  %8s  %9s  %-10s  %s\n", "FENÊTRE", "PAQUETS", "SYN-ONLY", "Z-SCORE", "STATUT", "DIAGNOSTIC")
	fmt.Println("--------------------------------------------------------------------------------")

	var history baseline.WelfordState
	for idx, win := range windows {
		verdict := detection.EvaluateWindow(win, history, policy)
		history = verdict.UpdatedHistory
		summary := "-"
		if len(verdict.Findings) > 0 {
			f := verdict.Findings[0]
			summary = fmt.Sprintf("%s depuis %s (ports=%d, syn=%d)", f.Reason, f.SourceIP, f.DistinctPorts, f.SynOnlyCount)
		}
		fmt.Printf(
			"#%-7d  %8d  %8d  %+9.2f  %-10s  %s\n",
			idx+1, verdict.TotalPackets, verdict.TotalSynOnly, verdict.SynRateZScore, verdict.Severity, summary,
		)
	}
}

func buildNormalWindow(start time.Time, synCount int) []packet.TCPEvent {
	client := netip.MustParseAddr("10.0.1.24")
	server := netip.MustParseAddr("10.0.2.10")
	var out []packet.TCPEvent
	for i := range synCount {
		out = append(out,
			packet.TCPEvent{ObservedAt: start, SourceIP: client, DestIP: server, SourcePort: uint16(40000 + i), DestPort: 443, Flags: packet.FlagSYN},
			packet.TCPEvent{ObservedAt: start, SourceIP: server, DestIP: client, SourcePort: 443, DestPort: uint16(40000 + i), Flags: packet.FlagSYN | packet.FlagACK},
		)
	}
	return out
}

func buildPortScanWindow(start time.Time, portCount int) []packet.TCPEvent {
	scanner := netip.MustParseAddr("192.168.1.99")
	target := netip.MustParseAddr("10.0.2.10")
	var out []packet.TCPEvent
	for p := range portCount {
		out = append(out, packet.TCPEvent{
			ObservedAt: start, SourceIP: scanner, DestIP: target,
			SourcePort: 53100, DestPort: uint16(20 + p), Flags: packet.FlagSYN,
		})
	}
	return out
}

func buildSynFloodWindow(start time.Time, synBurst int) []packet.TCPEvent {
	attacker := netip.MustParseAddr("203.0.113.77")
	target := netip.MustParseAddr("10.0.2.10")
	var out []packet.TCPEvent
	for i := range synBurst {
		out = append(out, packet.TCPEvent{
			ObservedAt: start, SourceIP: attacker, DestIP: target,
			SourcePort: uint16(10000 + i), DestPort: 443, Flags: packet.FlagSYN,
		})
	}
	return out
}
