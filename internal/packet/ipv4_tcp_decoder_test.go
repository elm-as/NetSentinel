package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func buildRawEthernetTCPFrame(srcPort, dstPort uint16, flags TCPFlags) []byte {
	frame := make([]byte, 14+20+20+8)
	// Ethernet : EtherType IPv4 (0x0800)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	// IPv4 : version=4, IHL=5 (20 octets), TotalLength=48, Protocol=6 (TCP)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 48)
	ip[9] = ipProtocolTCP
	copy(ip[12:16], []byte{192, 168, 10, 5})
	copy(ip[16:20], []byte{10, 0, 0, 80})

	// TCP : DataOffset=5 (20 octets)
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	tcp[13] = byte(flags)
	return frame
}

func TestDecodeEthernetIPv4TCP(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	raw := buildRawEthernetTCPFrame(51234, 443, FlagSYN)

	ev, err := DecodeEthernetIPv4TCP(raw, now)
	if err != nil {
		t.Fatalf("décodage inattendu en échec : %v", err)
	}
	if ev.SourceIP.String() != "192.168.10.5" || ev.DestIP.String() != "10.0.0.80" {
		t.Fatalf("adresses IP incorrectes : %s -> %s", ev.SourceIP, ev.DestIP)
	}
	if ev.SourcePort != 51234 || ev.DestPort != 443 {
		t.Fatalf("ports incorrects : %d -> %d", ev.SourcePort, ev.DestPort)
	}
	if !ev.Flags.IsSYNOnly() || ev.PayloadLen != 8 {
		t.Fatalf("drapeaux ou payload incorrects : flags=%v payload=%d", ev.Flags, ev.PayloadLen)
	}
}

func TestReadPCAPTCPStream(t *testing.T) {
	var buf bytes.Buffer

	// En-tête global PCAP little-endian (24 octets)
	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], pcapMagicMicroLE)
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)
	binary.LittleEndian.PutUint32(ghdr[20:24], linkTypeEthernet)
	buf.Write(ghdr[:])

	// Enregistrement PCAP d'une trame TCP SYN
	frame := buildRawEthernetTCPFrame(49100, 22, FlagSYN)
	var rhdr [16]byte
	binary.LittleEndian.PutUint32(rhdr[0:4], 1793360000)
	binary.LittleEndian.PutUint32(rhdr[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rhdr[12:16], uint32(len(frame)))
	buf.Write(rhdr[:])
	buf.Write(frame)

	events, err := ReadPCAPTCPStream(&buf)
	if err != nil {
		t.Fatalf("lecture PCAP échouée : %v", err)
	}
	if len(events) != 1 || events[0].DestPort != 22 {
		t.Fatalf("résultat PCAP inattendu : %+v", events)
	}
}
