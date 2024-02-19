package main

// Helper methods used to store/fetch keys in MacOS keychain

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"github.com/digitalocean/godo"
	"golang.org/x/term"
)

const digitalOceanKeychainKey string = "EWVM: DigitalOcean API token"
const privateSSHKeychainKey string = "EWVM: Private SSH key"
const publicSSHKeychainKey string = "EWVM: Public SSH key"

var validKeyChainServiceKeys = map[string]bool{
	digitalOceanKeychainKey: true,
	privateSSHKeychainKey:   true,
	publicSSHKeychainKey:    true,
}

func getKeychainKey(key string) (string, error) {
	if !validKeyChainServiceKeys[key] {
		return "", errors.New("invalid service name when getting keychain key")
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	username := currentUser.Username

	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", key, "-a", username, "-w").Output()
	if err != nil {
		return "", err
	}

	trimmedOutput := strings.TrimSpace(string(out))
	outputBytes, err := base64.StdEncoding.DecodeString(trimmedOutput)
	if err != nil {
		return "", err
	}

	return string(outputBytes), nil
}

func setKeychainKey(key string, value string) error {
	if !validKeyChainServiceKeys[key] {
		return errors.New("invalid service name when setting keychain key")
	}

	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	username := currentUser.Username

	cmd := exec.Command("/usr/bin/security", "-i")

	stdIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err = cmd.Start(); err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	command := fmt.Sprintf("add-generic-password -U -s '%s' -a %s -w %s\n", key, username, encoded)
	if len(command) > 4000 {
		return errors.New("input too large for /usr/bin/security to handle interactively via stdin")
	}
	if _, err := io.WriteString(stdIn, command); err != nil {
		return err
	}

	if err = stdIn.Close(); err != nil {
		return err
	}

	if err = cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func clearKeychainKey(key string) error {
	if !validKeyChainServiceKeys[key] {
		return errors.New("invalid service name when setting keychain key")
	}

	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	username := currentUser.Username

	_, err = exec.Command("/usr/bin/security", "delete-generic-password", "-s", key, "-a", username).Output()
	return err
}

func validateOrPromptApiKeySetup() *godo.Client {
	apiKey, err := getKeychainKey(digitalOceanKeychainKey)
	if err != nil {
		// No API key at all, collect from user
		apiKey = collectDigitalOceanAPIKey()
	}

	client := godo.NewFromToken(apiKey)
	_, resp, err := client.Account.Get(context.TODO())
	if err != nil {
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			Fatalf(fmt.Sprintf("Received %d status code authenticating to DigitalOcean. It may be down: https://status.digitalocean.com/\n\n", resp.StatusCode))
		} else {
			fmt.Printf("\nAPI token is invalid. Re-enter a valid token.\n\n")
			// API key exists but is not valid against the API, collect from user
			apiKey = collectDigitalOceanAPIKey()
		}
	}

	client = godo.NewFromToken(apiKey)
	_, resp, err = client.Account.Get(context.TODO())
	if err != nil {
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			Fatalf(fmt.Sprintf("Received %d status code authenticating to DigitalOcean. It may be down: https://status.digitalocean.com/\n\n", resp.StatusCode))
		} else {
			// Fresh token collected from the user but is still not valid.
			Fatalf("\nCould not collect a valid API token from the user: %s\n", err)
		}
	}

	return client
}

func hasValidApiKeyConfigured() bool {
	apiKey, err := getKeychainKey(digitalOceanKeychainKey)
	if err != nil {
		return false
	}

	client := godo.NewFromToken(apiKey)
	_, _, err = client.Account.Get(context.TODO())
	return err == nil
}

func collectDigitalOceanAPIKey() string {
	fmt.Print("Enter DigitalOcean API key: ")
	keyBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		Fatalf("Unable to collect API key from user: %s\n", err)
	}

	err = setKeychainKey(digitalOceanKeychainKey, string(keyBytes))
	if err != nil {
		Fatalf("Unable to set API key in keychain: %s\n", err)
	}

	fmt.Printf("\n\n")

	return string(keyBytes)
}
