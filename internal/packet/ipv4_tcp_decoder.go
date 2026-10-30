// Package packet décode les trames Ethernet/IPv4/TCP brutes sans dépendance C externe.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

const (
	ethernetHeaderLen = 14
	etherTypeIPv4     = 0x0800
	minIPv4HeaderLen  = 20
	minTCPHeaderLen   = 20
	ipProtocolTCP     = 6
)

// TCPFlags regroupe les bits de contrôle pertinents pour l'analyse comportementale.
type TCPFlags uint8

const (
	FlagFIN TCPFlags = 0x01
	FlagSYN TCPFlags = 0x02
	FlagRST TCPFlags = 0x04
	FlagPSH TCPFlags = 0x08
	FlagACK TCPFlags = 0x10
)

// IsSYNOnly identifie une demande d'ouverture de connexion initiale (sans acquittement).
// Un ratio élevé de paquets SYN-only par rapport aux SYN-ACK signale un scan ou un flood.
func (f TCPFlags) IsSYNOnly() bool {
	return (f&FlagSYN != 0) && (f&FlagACK == 0)
}

// IsSYNACK identifie la réponse d'un service ouvert acceptant la poignée de main TCP.
func (f TCPFlags) IsSYNACK() bool {
	return (f&FlagSYN != 0) && (f&FlagACK != 0)
}

// HasRST signale un rejet immédiat, typique d'un port fermé lors d'un balayage.
func (f TCPFlags) HasRST() bool {
	return f&FlagRST != 0
}

// TCPEvent représente une observation réseau immuable extraite d'une trame brute.
type TCPEvent struct {
	ObservedAt time.Time
	SourceIP   netip.Addr
	DestIP     netip.Addr
	SourcePort uint16
	DestPort   uint16
	Flags      TCPFlags
	PayloadLen int
}

var (
	ErrFrameTooShort   = errors.New("trame trop courte pour contenir Ethernet + IPv4 + TCP")
	ErrUnsupportedLink = errors.New("seul EtherType IPv4 (0x0800) est pris en charge")
	ErrInvalidIPHeader = errors.New("en-tête IPv4 malformé ou longueur IHL invalide")
	ErrNotTCPProtocol  = errors.New("protocole de transport différent de TCP (6)")
)

// DecodeEthernetIPv4TCP extrait un événement TCP immuable depuis une trame Ethernet brute.
// Retourne une erreur typée explicite si la trame est tronquée, non-IPv4 ou non-TCP.
func DecodeEthernetIPv4TCP(rawFrame []byte, observedAt time.Time) (TCPEvent, error) {
	if len(rawFrame) < ethernetHeaderLen+minIPv4HeaderLen+minTCPHeaderLen {
		return TCPEvent{}, ErrFrameTooShort
	}

	etherType := binary.BigEndian.Uint16(rawFrame[12:14])
	if etherType != etherTypeIPv4 {
		return TCPEvent{}, ErrUnsupportedLink
	}

	ipSlice := rawFrame[ethernetHeaderLen:]
	version := ipSlice[0] >> 4
	ihlBytes := int(ipSlice[0]&0x0f) * 4
	if version != 4 || ihlBytes < minIPv4HeaderLen || len(ipSlice) < ihlBytes+minTCPHeaderLen {
		return TCPEvent{}, ErrInvalidIPHeader
	}

	if ipSlice[9] != ipProtocolTCP {
		return TCPEvent{}, ErrNotTCPProtocol
	}

	totalIPLen := int(binary.BigEndian.Uint16(ipSlice[2:4]))
	srcAddr, _ := netip.AddrFromSlice(ipSlice[12:16])
	dstAddr, _ := netip.AddrFromSlice(ipSlice[16:20])

	tcpSlice := ipSlice[ihlBytes:]
	dataOffsetBytes := int(tcpSlice[12]>>4) * 4
	if dataOffsetBytes < minTCPHeaderLen || len(tcpSlice) < dataOffsetBytes {
		return TCPEvent{}, ErrFrameTooShort
	}

	payloadLen := max(0, totalIPLen-ihlBytes-dataOffsetBytes)

	return TCPEvent{
		ObservedAt: observedAt,
		SourceIP:   srcAddr,
		DestIP:     dstAddr,
		SourcePort: binary.BigEndian.Uint16(tcpSlice[0:2]),
		DestPort:   binary.BigEndian.Uint16(tcpSlice[2:4]),
		Flags:      TCPFlags(tcpSlice[13]),
		PayloadLen: payloadLen,
	}, nil
}
