package analysis

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
)

// PCAP global header (24 bytes).
type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// PCAP record header (16 bytes).
type pcapRecordHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// Ethernet header constants.
const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeARP  = 0x0806
)

// IP protocol constants.
const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// AnalyzeNetwork performs triage analysis on PCAP/PCAPNG files.
func AnalyzeNetwork(path string) (*models.NetworkAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	defer f.Close()

	// Read magic to determine format.
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return nil, fmt.Errorf("reading pcap magic: %w", err)
	}
	f.Seek(0, 0)

	magicVal := binary.BigEndian.Uint32(magic[:])

	switch magicVal {
	case 0xA1B2C3D4: // PCAP big-endian
		return analyzePCAP(f, binary.BigEndian)
	case 0xD4C3B2A1: // PCAP little-endian
		return analyzePCAP(f, binary.LittleEndian)
	case 0x0A0D0D0A: // PCAPNG
		return analyzePCAPNG(f)
	default:
		return nil, fmt.Errorf("unrecognized pcap magic: 0x%08X", magicVal)
	}
}

// analyzePCAP parses a classic PCAP file.
func analyzePCAP(f *os.File, order binary.ByteOrder) (*models.NetworkAnalysis, error) {
	result := &models.NetworkAnalysis{}
	protocolSet := make(map[string]bool)
	connMap := make(map[string]*models.NetConnection)
	dnsMap := make(map[string]bool)
	var httpRequests []models.HTTPRequest
	var tlsInfo []models.TLSConnection

	// Read global header.
	var gh pcapGlobalHeader
	if err := binary.Read(f, order, &gh); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}

	// Read packets.
	packetCount := 0
	maxPackets := 100000 // Safety limit.

	for packetCount < maxPackets {
		var rh pcapRecordHeader
		if err := binary.Read(f, order, &rh); err != nil {
			break // EOF or error — normal termination.
		}

		if rh.InclLen == 0 || rh.InclLen > 65535 {
			break
		}

		packetData := make([]byte, rh.InclLen)
		n, err := f.Read(packetData)
		if err != nil || n < int(rh.InclLen) {
			break
		}

		packetCount++
		processPacket(packetData, gh.Network, protocolSet, connMap, dnsMap, &httpRequests, &tlsInfo)
	}

	result.TotalPackets = packetCount

	// Convert protocol set to sorted slice.
	for proto := range protocolSet {
		result.Protocols = append(result.Protocols, proto)
	}
	sort.Strings(result.Protocols)

	// Convert connection map to sorted slice.
	for _, conn := range connMap {
		result.Connections = append(result.Connections, *conn)
	}
	sort.Slice(result.Connections, func(i, j int) bool {
		return result.Connections[i].Count > result.Connections[j].Count
	})
	// Cap at top 50 connections.
	if len(result.Connections) > 50 {
		result.Connections = result.Connections[:50]
	}

	// DNS queries.
	for domain := range dnsMap {
		result.DNSQueries = append(result.DNSQueries, models.DNSQuery{
			Domain: domain,
			Type:   "A",
		})
	}
	sort.Slice(result.DNSQueries, func(i, j int) bool {
		return result.DNSQueries[i].Domain < result.DNSQueries[j].Domain
	})

	result.HTTPRequests = httpRequests
	result.TLSInfo = tlsInfo

	// Detect beaconing patterns.
	result.Beacons = detectBeacons(connMap)

	return result, nil
}

// analyzePCAPNG performs lightweight PCAPNG analysis.
// PCAPNG has a more complex block-based format, so we do a simplified parse.
func analyzePCAPNG(f *os.File) (*models.NetworkAnalysis, error) {
	result := &models.NetworkAnalysis{}
	protocolSet := make(map[string]bool)
	connMap := make(map[string]*models.NetConnection)
	dnsMap := make(map[string]bool)
	var httpRequests []models.HTTPRequest
	var tlsInfo []models.TLSConnection

	stat, _ := f.Stat()
	readSize := stat.Size()
	if readSize > 100*1024*1024 {
		readSize = 100 * 1024 * 1024
	}

	data := make([]byte, readSize)
	n, _ := f.Read(data)
	data = data[:n]

	packetCount := 0
	offset := 0

	for offset+12 <= len(data) {
		// Each block: type (4 bytes) + total_length (4 bytes) + body + total_length (4 bytes)
		blockType := binary.LittleEndian.Uint32(data[offset : offset+4])
		blockLen := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

		if blockLen < 12 || offset+blockLen > len(data) {
			break
		}

		// Enhanced Packet Block (type 6) or Simple Packet Block (type 3).
		if blockType == 6 && blockLen > 28 {
			// EPB: Interface ID (4) + Timestamp (8) + Captured Len (4) + Original Len (4) = 20 bytes header.
			capturedLen := int(binary.LittleEndian.Uint32(data[offset+20 : offset+24]))
			packetStart := offset + 28
			if packetStart+capturedLen <= offset+blockLen && capturedLen > 0 && capturedLen <= 65535 {
				packetData := data[packetStart : packetStart+capturedLen]
				packetCount++
				processPacket(packetData, 1, protocolSet, connMap, dnsMap, &httpRequests, &tlsInfo)
			}
		}

		offset += blockLen
		// Align to 4-byte boundary.
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}

		if packetCount >= 100000 {
			break
		}
	}

	result.TotalPackets = packetCount

	for proto := range protocolSet {
		result.Protocols = append(result.Protocols, proto)
	}
	sort.Strings(result.Protocols)

	for _, conn := range connMap {
		result.Connections = append(result.Connections, *conn)
	}
	sort.Slice(result.Connections, func(i, j int) bool {
		return result.Connections[i].Count > result.Connections[j].Count
	})
	if len(result.Connections) > 50 {
		result.Connections = result.Connections[:50]
	}

	for domain := range dnsMap {
		result.DNSQueries = append(result.DNSQueries, models.DNSQuery{
			Domain: domain,
			Type:   "A",
		})
	}
	sort.Slice(result.DNSQueries, func(i, j int) bool {
		return result.DNSQueries[i].Domain < result.DNSQueries[j].Domain
	})

	result.HTTPRequests = httpRequests
	result.TLSInfo = tlsInfo
	result.Beacons = detectBeacons(connMap)

	return result, nil
}

// processPacket extracts information from a single network packet.
func processPacket(pkt []byte, linkType uint32, protocols map[string]bool,
	connMap map[string]*models.NetConnection, dnsMap map[string]bool,
	httpReqs *[]models.HTTPRequest, tlsInfo *[]models.TLSConnection) {

	var ipPayload []byte
	var srcIP, dstIP string
	var ipProto uint8

	switch linkType {
	case 1: // Ethernet
		if len(pkt) < 14 {
			return
		}
		etherType := binary.BigEndian.Uint16(pkt[12:14])
		switch etherType {
		case etherTypeIPv4:
			protocols["IPv4"] = true
			ipPayload, srcIP, dstIP, ipProto = parseIPv4(pkt[14:])
		case etherTypeIPv6:
			protocols["IPv6"] = true
			return // Simplified: skip IPv6 deep parsing for now.
		case etherTypeARP:
			protocols["ARP"] = true
			return
		default:
			return
		}
	case 101: // Raw IP
		if len(pkt) < 20 {
			return
		}
		version := pkt[0] >> 4
		if version == 4 {
			protocols["IPv4"] = true
			ipPayload, srcIP, dstIP, ipProto = parseIPv4(pkt)
		}
		return
	default:
		return
	}

	if ipPayload == nil {
		return
	}

	var srcPort, dstPort int

	switch ipProto {
	case ipProtoTCP:
		protocols["TCP"] = true
		if len(ipPayload) < 20 {
			return
		}
		srcPort = int(binary.BigEndian.Uint16(ipPayload[0:2]))
		dstPort = int(binary.BigEndian.Uint16(ipPayload[2:4]))

		dataOffset := int((ipPayload[12] >> 4) * 4)
		if dataOffset > 0 && dataOffset < len(ipPayload) {
			tcpPayload := ipPayload[dataOffset:]

			// Check for HTTP.
			if dstPort == 80 || dstPort == 8080 {
				protocols["HTTP"] = true
				if req := parseHTTPRequest(tcpPayload); req != nil {
					if len(*httpReqs) < 100 {
						*httpReqs = append(*httpReqs, *req)
					}
				}
			}

			// Check for TLS ClientHello.
			if dstPort == 443 || dstPort == 8443 {
				protocols["TLS"] = true
				if sni := parseTLSSNI(tcpPayload); sni != "" {
					if len(*tlsInfo) < 100 {
						*tlsInfo = append(*tlsInfo, models.TLSConnection{
							ServerName: sni,
						})
					}
				}
			}
		}

	case ipProtoUDP:
		protocols["UDP"] = true
		if len(ipPayload) < 8 {
			return
		}
		srcPort = int(binary.BigEndian.Uint16(ipPayload[0:2]))
		dstPort = int(binary.BigEndian.Uint16(ipPayload[2:4]))

		// Check for DNS (port 53).
		if dstPort == 53 || srcPort == 53 {
			protocols["DNS"] = true
			if domain := parseDNSQuery(ipPayload[8:]); domain != "" {
				dnsMap[domain] = true
			}
		}

	default:
		return
	}

	// Track connection.
	connKey := fmt.Sprintf("%s:%d->%s:%d/%d", srcIP, srcPort, dstIP, dstPort, ipProto)
	if conn, ok := connMap[connKey]; ok {
		conn.Count++
	} else {
		proto := "TCP"
		if ipProto == ipProtoUDP {
			proto = "UDP"
		}
		connMap[connKey] = &models.NetConnection{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
			Proto:   proto,
			Count:   1,
		}
	}
}

// parseIPv4 extracts basic IPv4 header info.
func parseIPv4(data []byte) (payload []byte, srcIP, dstIP string, proto uint8) {
	if len(data) < 20 {
		return nil, "", "", 0
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, "", "", 0
	}

	proto = data[9]
	srcIP = net.IP(data[12:16]).String()
	dstIP = net.IP(data[16:20]).String()
	payload = data[ihl:]

	return payload, srcIP, dstIP, proto
}

// parseDNSQuery extracts the queried domain from a DNS payload.
func parseDNSQuery(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Check QR bit — we want queries (QR=0).
	flags := binary.BigEndian.Uint16(data[2:4])
	isQuery := flags&0x8000 == 0
	if !isQuery {
		return ""
	}

	qdCount := binary.BigEndian.Uint16(data[4:6])
	if qdCount == 0 {
		return ""
	}

	// Parse domain name starting at offset 12.
	offset := 12
	var parts []string

	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			break
		}
		if labelLen&0xC0 == 0xC0 {
			break // Compressed label — skip.
		}
		offset++
		if offset+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(parts) >= 2 {
		return strings.Join(parts, ".")
	}
	return ""
}

// parseHTTPRequest extracts HTTP method, URL, and user-agent from raw TCP payload.
func parseHTTPRequest(data []byte) *models.HTTPRequest {
	if len(data) < 16 {
		return nil
	}

	// Check for HTTP method.
	s := string(data[:min(len(data), 4096)])
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	var method, path string

	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			method = strings.TrimSpace(m)
			// Extract path.
			rest := s[len(m):]
			if idx := strings.Index(rest, " "); idx > 0 {
				path = rest[:idx]
			}
			break
		}
	}

	if method == "" {
		return nil
	}

	req := &models.HTTPRequest{
		Method: method,
		URL:    path,
	}

	// Extract Host header.
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			req.Host = strings.TrimSpace(line[5:])
		}
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			req.UserAgent = strings.TrimSpace(line[11:])
		}
	}

	if req.Host != "" {
		req.URL = req.Host + path
	}

	return req
}

// parseTLSSNI extracts the Server Name Indication from a TLS ClientHello.
func parseTLSSNI(data []byte) string {
	// TLS record: content_type (1) + version (2) + length (2) + handshake.
	if len(data) < 44 {
		return ""
	}

	// Content type 22 = Handshake.
	if data[0] != 22 {
		return ""
	}

	// Handshake type 1 = ClientHello.
	if len(data) < 6 || data[5] != 1 {
		return ""
	}

	// Skip to extensions. ClientHello structure:
	// handshake_type(1) + length(3) + version(2) + random(32) + session_id_len(1) + session_id + ...
	offset := 5 + 1 + 3 + 2 + 32 // Position at session_id_len
	if offset >= len(data) {
		return ""
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites length (2 bytes).
	if offset+2 > len(data) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherLen

	// Compression methods length (1 byte).
	if offset+1 > len(data) {
		return ""
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions length (2 bytes).
	if offset+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extLen

	// Parse extensions looking for SNI (type 0).
	for offset+4 <= len(data) && offset < extEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if extType == 0 && extDataLen > 5 && offset+extDataLen <= len(data) {
			// SNI extension: list_length(2) + type(1) + name_length(2) + name.
			sniOffset := offset + 2 + 1
			if sniOffset+2 > len(data) {
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[sniOffset : sniOffset+2]))
			sniOffset += 2
			if sniOffset+nameLen <= len(data) && nameLen > 0 {
				return string(data[sniOffset : sniOffset+nameLen])
			}
		}

		offset += extDataLen
	}

	return ""
}

// detectBeacons looks for periodic communication patterns.
func detectBeacons(connMap map[string]*models.NetConnection) []models.BeaconPattern {
	var beacons []models.BeaconPattern

	// Simple heuristic: connections with high repeat count to the same dst.
	dstCounts := make(map[string]int)
	for _, conn := range connMap {
		key := fmt.Sprintf("%s:%d", conn.DstIP, conn.DstPort)
		dstCounts[key] += conn.Count
	}

	for key, count := range dstCounts {
		if count >= 10 { // Threshold for potential beaconing.
			var ip string
			var port int
			fmt.Sscanf(key, "%[^:]:%d", &ip, &port)

			// Skip common/expected ports.
			if port == 53 || port == 80 || port == 443 {
				if count < 50 {
					continue
				}
			}

			beacons = append(beacons, models.BeaconPattern{
				DstIP:   ip,
				DstPort: port,
				Count:   count,
			})
		}
	}

	sort.Slice(beacons, func(i, j int) bool {
		return beacons[i].Count > beacons[j].Count
	})

	if len(beacons) > 20 {
		beacons = beacons[:20]
	}

	return beacons
}
