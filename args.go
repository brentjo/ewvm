package main

// Helper methods used in argument parsing

import (
	"net"
	"regexp"
)

func validRegion(r string) bool {
	match, err := regexp.MatchString("^[a-zA-Z]{3}[0-9]?$", r)
	return err == nil && match
}

func validServerIP(ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}

	ip4 := netIP.To4()
	if ip4 == nil {
		return false
	}

	lastOctal := int(ip4[3])

	return netIP.IsPrivate() && lastOctal < 255
}

func validDNS(dnsServer string) bool {
	netIP := net.ParseIP(dnsServer)
	if netIP == nil {
		return false
	}
	netIP.DefaultMask()

	return netIP.To4() != nil
}

func clientIP(serverIP string) string {
	ip := net.ParseIP(serverIP).To4()
	ip[3]++
	return ip.String()
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}
