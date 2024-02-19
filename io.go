package main

// Helper methods used for config file handling

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const configDirectoryName = ".ewvm"

func WriteFile(name string, data []byte, perm fs.FileMode) error {
	if _, err := os.Stat(configDirectory()); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(configDirectory(), 0700)
		if err != nil {
			Fatalf("Error creating config file directory at %s: %s", configDirectory(), err)
		}
	}

	targetFilePath := filepath.Join(configDirectory(), name)
	if err := os.WriteFile(targetFilePath, data, perm); err != nil {
		return err
	}

	return nil
}

func ReadFile(name string) ([]byte, error) {
	if _, err := os.Stat(configDirectory()); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(configDirectory(), 0700)
		if err != nil {
			Fatalf("Error creating config file directory at %s: %s", configDirectory(), err)
		}
	}

	targetFilePath := filepath.Join(configDirectory(), name)

	return os.ReadFile(targetFilePath)
}

func copyToClipboard(content string) error {
	cmd := exec.Command("/usr/bin/pbcopy")

	stdIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err = cmd.Start(); err != nil {
		return err
	}

	if _, err := io.WriteString(stdIn, content); err != nil {
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

func baseConfigDirectory() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		Fatalf("Error getting user's home directory: %s", err)
	}

	return homeDir
}

func configDirectory() string {
	return filepath.Join(baseConfigDirectory(), configDirectoryName)
}

func setLogFile(name string) *os.File {
	if _, err := os.Stat(configDirectory()); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(configDirectory(), 0700)
		if err != nil {
			Fatalf("Error creating config file directory at %s: %s", configDirectory(), err)
		}
	}

	targetFilePath := filepath.Join(configDirectory(), name)

	logFile, err := os.OpenFile(targetFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0700)
	if err != nil {
		Fatalf("Error creating logger: %s", err)
	}

	log.SetOutput(logFile)

	return logFile
}

// Small wrapper over Fatalf so that any Fatalf's both write to the verbose log file configured for it,
// and to stdout so the user sees what went wrong
func Fatalf(format string, v ...any) {
	fmt.Println(fmt.Sprintf(format, v...))
	log.Fatalf(format, v...)
}
