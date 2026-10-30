package packet

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16
	pcapMagicMicroLE    = 0xa1b2c3d4
	pcapMagicMicroBE    = 0xd4c3b2a1
	linkTypeEthernet    = 1
	maxCapturedFrameLen = 65535
)

var (
	ErrInvalidPCAPMagic = errors.New("signature PCAP non reconnue (format microsecondes attendu)")
	ErrUnsupportedDLT   = errors.New("type de liaison PCAP non supporté (Ethernet DLT_EN10MB requis)")
	ErrCorruptPCAPEntry = errors.New("enregistrement PCAP corrompu : taille capturée excessive")
)

// ReadPCAPTCPStream lit un flux binaire .pcap standard et extrait les événements TCP valides.
// Les trames non-IPv4 ou non-TCP (ARP, UDP, ICMP, IPv6) sont ignorées sans interrompre l'analyse.
func ReadPCAPTCPStream(reader io.Reader) ([]TCPEvent, error) {
	var globalHdr [pcapGlobalHeaderLen]byte
	if _, err := io.ReadFull(reader, globalHdr[:]); err != nil {
		return nil, err
	}

	byteOrder, err := resolvePCAPByteOrder(globalHdr[:])
	if err != nil {
		return nil, err
	}

	linkType := byteOrder.Uint32(globalHdr[20:24])
	if linkType != linkTypeEthernet {
		return nil, ErrUnsupportedDLT
	}

	var events []TCPEvent
	var recHdr [pcapRecordHeaderLen]byte
	frameBuf := make([]byte, maxCapturedFrameLen)

	for {
		_, err := io.ReadFull(reader, recHdr[:])
		if errors.Is(err, io.EOF) {
			return events, nil
		}
		if err != nil {
			return nil, err
		}

		tsSec := int64(byteOrder.Uint32(recHdr[0:4]))
		tsUsec := int64(byteOrder.Uint32(recHdr[4:8]))
		capturedLen := int(byteOrder.Uint32(recHdr[8:12]))
		if capturedLen <= 0 || capturedLen > maxCapturedFrameLen {
			return nil, ErrCorruptPCAPEntry
		}

		if _, err := io.ReadFull(reader, frameBuf[:capturedLen]); err != nil {
			return nil, err
		}

		timestamp := time.Unix(tsSec, tsUsec*1000).UTC()
		event, decodeErr := DecodeEthernetIPv4TCP(frameBuf[:capturedLen], timestamp)
		if decodeErr == nil {
			events = append(events, event)
		}
	}
}

func resolvePCAPByteOrder(header []byte) (binary.ByteOrder, error) {
	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic == pcapMagicMicroLE {
		return binary.LittleEndian, nil
	}
	if magic == pcapMagicMicroBE {
		return binary.BigEndian, nil
	}
	return nil, ErrInvalidPCAPMagic
}
