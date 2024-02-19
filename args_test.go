package main

import "testing"

func TestValidRegion(t *testing.T) {
	if !validRegion("sfo3") {
		t.Errorf("Expected a valid region")
	}

	if !validRegion("sfo") {
		t.Errorf("Expected a valid region")
	}

	if validRegion("notdatacentercode") {
		t.Errorf("Expected an invalid region")
	}

	if validRegion("before\nsfo3") {
		t.Errorf("Expected an invalid region")
	}

	if validRegion("sf") {
		t.Errorf("Expected an invalid region")
	}

	if validRegion("sf3") {
		t.Errorf("Expected an invalid region")
	}
}

func TestValidServerIP(t *testing.T) {
	if !validServerIP("10.0.8.1") {
		t.Errorf("Expected a valid server IP")
	}

	if validServerIP("10.0.8.256") {
		t.Errorf("Expected an invalid server IP")
	}

	if validServerIP("8.8.8.8") {
		t.Errorf("Expected an public IP to be considered invalid")
	}

	if validServerIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334") {
		t.Errorf("Expected an invalid server IP")
	}

	if validServerIP("texthere") {
		t.Errorf("Expected an invalid server IP")
	}

	if validServerIP("0") {
		t.Errorf("Expected an invalid server IP")
	}
}

func TestValidDNS(t *testing.T) {

	if !validDNS("8.8.8.8") {
		t.Errorf("Expected a valid DNS address")
	}

	if validDNS("2001:0db8:85a3:0000:0000:8a2e:0370:7334") {
		t.Errorf("Expected an invalid DNS address")
	}

	if validDNS("texthere") {
		t.Errorf("Expected an invalid DNS address")
	}

	if validDNS("0") {
		t.Errorf("Expected an invalid DNS address")
	}
}

func TestClientIP(t *testing.T) {
	if clientIP("10.0.8.1") != "10.0.8.2" {
		t.Errorf("Expected client IP to be next address of server")
	}
}

func TestValidPort(t *testing.T) {
	if !validPort(3000) {
		t.Errorf("Expected a valid port")
	}

	if validPort(0) {
		t.Errorf("Expected an invalid DNS address")
	}
	if validPort(-1) {
		t.Errorf("Expected an invalid DNS address")
	}
	if validPort(65536) {
		t.Errorf("Expected an invalid DNS address")
	}
}
