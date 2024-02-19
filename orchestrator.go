package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

const dropletTagName string = "ewvm-temporary-machine"
const sshKeyName string = "ephemeral-wg-key"
const knownHostsFileName = "known_hosts"
const wgConfFileName string = "ewvm.conf"
const challengeFile = "/bootstrap-challenge"

//go:embed listen.py
var pythonScript embed.FS

type Orchestrator struct {
	Client           *godo.Client
	Region           string
	ClientInternalIP string
	ServerInternalIP string
	DNS              string
	DropletID        int
	DropletIP        string
	SSHKeyID         int
	SSHPublicKey     []byte
	SSHPrivateKey    []byte
}

type Command struct {
	Text      string
	StdIn     io.Reader
	StdOut    io.Writer
	StdErr    io.Writer
	TrimSpace bool
}

func (o *Orchestrator) createSSHKey() {
	log.Println("Creating a new SSH key and adding it to the account")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		Fatalf("Error generating ed25519 key: %s", err)
	}
	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		Fatalf("Error creating new ssh public key from ed25519 public key: %s", err)
	}

	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	bytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	privateKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		},
	)

	if err := setKeychainKey(publicSSHKeychainKey, string(publicKeyBytes)); err != nil {
		Fatalf("Error setting public SSH key in keychain: %s", err)
	}
	if err := setKeychainKey(privateSSHKeychainKey, string(privateKeyBytes)); err != nil {
		Fatalf("Error setting private SSH key in keychain: %s", err)
	}

	o.SSHPublicKey = publicKeyBytes
	o.SSHPrivateKey = privateKeyBytes

	createKeyRequest := &godo.KeyCreateRequest{
		Name:      sshKeyName,
		PublicKey: string(publicKeyBytes),
	}
	key, _, err := o.Client.Keys.Create(context.TODO(), createKeyRequest)
	if err != nil {
		Fatalf("Error creating new SSH key on account: %s", err)
	}

	log.Printf("Created a new key on account with ID: %d\n", key.ID)
	o.SSHKeyID = key.ID
}

func (o *Orchestrator) createVM() string {
	log.Println("Creating a new VM")
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		Fatalf("Error generating challenge: %s\n", err)
	}
	challenge := hex.EncodeToString(bytes)
	userDataCommand := fmt.Sprintf("#cloud-config\nruncmd:\n - echo \"%s\" > %s\n", challenge, challengeFile)

	createRequest := &godo.DropletCreateRequest{
		Name:   "ewvm-machine",
		Region: o.Region,
		Size:   "s-1vcpu-1gb-amd",
		Image: godo.DropletCreateImage{
			Slug: "ubuntu-23-10-x64",
		},
		Monitoring: false,
		SSHKeys:    []godo.DropletCreateSSHKey{{ID: o.SSHKeyID}},
		Tags:       []string{dropletTagName},
		UserData:   userDataCommand,
	}

	newDroplet, _, err := o.Client.Droplets.Create(context.TODO(), createRequest)
	if err != nil {
		Fatalf("Error creating droplet: %s\n", err)
	}

	log.Printf("Created a new VM with ID: %d\n", newDroplet.ID)
	o.DropletID = newDroplet.ID
	return challenge
}

func (o *Orchestrator) dropletsOnAccount() (int, error) {
	droplets, _, err := o.Client.Droplets.ListByTag(context.TODO(), dropletTagName, &godo.ListOptions{})
	if err != nil {
		return 0, err
	}

	return len(droplets), nil
}

func (o *Orchestrator) setCurrentSSHKey() {
	log.Println("Getting current SSH keys from keychain")
	pub, err := getKeychainKey(publicSSHKeychainKey)
	if err != nil {
		Fatalf("Error fetching public ssh key: %s\n", err)
	}

	priv, err := getKeychainKey(privateSSHKeychainKey)
	if err != nil {
		Fatalf("Error fetching private ssh key: %s\n", err)
	}

	o.SSHPublicKey = []byte(pub)
	o.SSHPrivateKey = []byte(priv)
}

func (o *Orchestrator) setCurrentDropletID() error {
	log.Println("Looking for current droplet VM")

	droplets, _, err := o.Client.Droplets.ListByTag(context.TODO(), dropletTagName, &godo.ListOptions{})
	if err != nil {
		return err
	}

	if len(droplets) > 1 {
		fmt.Println("Found two ephemeral droplets on your account. You may want to run 'ewvm down' to get into a fresh state.")
		os.Exit(0)
	} else if len(droplets) == 0 {
		fmt.Println("Could not find any active ephemeral VMs on your account. First bring one up with `ewvm up`")
		os.Exit(0)
	} else {
		log.Printf("Found current droplet with ID: %d\n", droplets[0].ID)
		o.DropletID = droplets[0].ID
	}

	return nil
}

func (o *Orchestrator) setCurrentDropletIP() {
	log.Println("Looking for current droplet VM's IP address")

	droplet, _, err := o.Client.Droplets.Get(context.TODO(), o.DropletID)
	if err != nil {
		Fatalf("Error fetching IP for current droplet: %s\n", err)
	}

	ip, err := droplet.PublicIPv4()
	if err != nil {
		Fatalf("Error fetching IP for current droplet: %s\n", err)
	}

	if len(ip) > 0 {
		log.Printf("Found current droplet IP of: %s\n", ip)
		o.DropletIP = ip
	} else {
		Fatalf("Found no publics IPs for droplet")
	}
}

func (o *Orchestrator) attemptSSHBootstrap(expectedChallenge string) error {
	receivedChallenge, hostKey, err := o.fetchSSHChallenge()
	if err != nil {
		return err
	}

	log.Printf("Received back: %s\n", receivedChallenge)
	if receivedChallenge == expectedChallenge {
		log.Println("Challenge validated. Saving to known hosts...")
		if err := WriteFile(knownHostsFileName, []byte(hostKey), 0600); err != nil {
			Fatalf("Error writing known_hosts file: %s", err)
		}
	} else {
		Fatalf("Challenge result did not match")
	}

	return nil
}

func (o *Orchestrator) fetchSSHChallenge() (string, string, error) {
	log.Println("Fetching SSH challenge")

	key, err := ssh.ParsePrivateKey(o.SSHPrivateKey)
	if err != nil {
		return "", "", err
	}

	var hostKey string
	config := &ssh.ClientConfig{
		User: "root",
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			hostWithoutPort := host[:len(host)-3]
			marshalledPublicKey := string(ssh.MarshalAuthorizedKey(pubKey))
			hostKey = fmt.Sprintf("%s %s", hostWithoutPort, marshalledPublicKey)
			return nil
		}),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(o.DropletIP, "22"), config)
	if err != nil {
		return "", "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()
	var outBuffer bytes.Buffer
	session.Stdout = &outBuffer

	err = session.Run(fmt.Sprintf("cat %s", challengeFile))

	foundChallenge := strings.TrimSpace(outBuffer.String())

	return foundChallenge, hostKey, err
}

func (o *Orchestrator) remoteCommand(cmd Command) (string, error) {
	log.Printf("Running remote command: %s\n", cmd.Text)

	key, err := ssh.ParsePrivateKey(o.SSHPrivateKey)
	if err != nil {
		return "", err
	}

	validateHostKeyCallback, err := knownhosts.New(filepath.Join(configDirectory(), knownHostsFileName))
	if err != nil {
		Fatalf("Could not create validateHostKeyCallback function: %s", err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: validateHostKeyCallback,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(o.DropletIP, "22"), config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var outBuffer bytes.Buffer

	if cmd.StdOut != nil {
		session.Stdout = cmd.StdOut
	} else {
		session.Stdout = &outBuffer
	}

	if cmd.StdErr != nil {
		session.Stderr = cmd.StdErr
	}

	if cmd.StdIn != nil {
		session.Stdin = cmd.StdIn
	}

	err = session.Run(cmd.Text)

	if cmd.TrimSpace {
		return strings.TrimSpace(outBuffer.String()), err
	} else {
		return outBuffer.String(), err
	}

}

func (o *Orchestrator) pollUntilPublicIP() {
	log.Printf("Polling droplet %d until a public IP is assigned\n", o.DropletID)

	for {
		droplet, _, err := o.Client.Droplets.Get(context.TODO(), o.DropletID)
		if err != nil {
			Fatalf("Error polling for public IP: %s\n", err)
		}

		ip, err := droplet.PublicIPv4()
		if err != nil {
			Fatalf("Error getting public IP of droplet: %s\n", err)
		}
		time.Sleep(3 * time.Second)
		if len(ip) > 0 {
			log.Printf("Found IP: %s\n", ip)
			o.DropletIP = ip
			return
		}
	}
}

func (o *Orchestrator) setupInitialSSHConnection(challenge string) {
	log.Printf("Expecting a challenge response of: %s\n", challenge)

	waitDuration := 10 * time.Second
	maxWait := 2 * time.Minute
	cyclesWaited := 0
	for {
		if time.Duration(cyclesWaited)*waitDuration > maxWait {
			o.destroyVMs()
			o.removeSSHKeysFromAccount()
			Fatalf("Timeout Reached. Could never bootstrap and validate initial SSH connection")
		}

		err := o.attemptSSHBootstrap(challenge)
		if err == nil {
			log.Println("SSH connection successfully bootstrapped")
			break
		} else {
			log.Println("SSH connection bootstrap failed. Re-attempting...")
			time.Sleep(waitDuration)
			cyclesWaited++
		}
	}
}

func (o *Orchestrator) waitForHostToBoot() {
	log.Println("Waiting for the host to boot")

	waitDuration := 5 * time.Second
	maxWait := 2 * time.Minute
	cyclesWaited := 0
	for {
		if time.Duration(cyclesWaited)*waitDuration > maxWait {
			Fatalf("Timeout reached. Could never open a connection to %s:22", o.DropletIP)
			break
		}

		timeout := time.Second
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(o.DropletIP, "22"), timeout)
		if err == nil && conn != nil {
			conn.Close()
			break
		}
		time.Sleep(waitDuration)
		cyclesWaited++
	}
}

func (o *Orchestrator) configureWireguard() {
	// Install wireguard command line tools
	_, err := o.remoteCommand(Command{Text: "sudo apt-get -o DPkg::Lock::Timeout=120 update"})
	if err != nil {
		Fatalf("Error running apt update on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo apt-get -o DPkg::Lock::Timeout=120 install -y wireguard"})
	if err != nil {
		Fatalf("Error apt installing Wireguard tools on remote host: %s", err)
	}

	// Generate public and private keys for the 'server' and 'client' wireguard peers
	serverPrivateKey, err := o.remoteCommand(Command{Text: "wg genkey | sudo tee /etc/wireguard/private.key", TrimSpace: true})
	if err != nil {
		Fatalf("Error generating server private key on remote host : %s", err)
	}

	serverPublicKey, err := o.remoteCommand(Command{Text: "sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key", TrimSpace: true})
	if err != nil {
		Fatalf("Error generating server public key on remote host: %s", err)
	}

	clientPrivateKey, err := o.remoteCommand(Command{Text: "wg genkey", TrimSpace: true})
	if err != nil {
		Fatalf("Error generating client private key on remote host: %s", err)
	}

	clientPublicKey, err := o.remoteCommand(Command{Text: "wg pubkey", StdIn: strings.NewReader(clientPrivateKey), TrimSpace: true})
	if err != nil {
		Fatalf("Error generating client public key on remote host : %s", err)
	}

	// Use the keys to create Wireguard config files for the client + server
	serverConfigFile := `[Interface]
Address = $SERVER_INTERNAL_IP/24
PostUp = ufw route allow in on wg0 out on eth0
PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on eth0
PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_INTERNAL_IP/32`

	serverConfigFile = strings.ReplaceAll(serverConfigFile, "$SERVER_INTERNAL_IP", o.ServerInternalIP)
	serverConfigFile = strings.ReplaceAll(serverConfigFile, "$SERVER_PRIVATE_KEY", serverPrivateKey)
	serverConfigFile = strings.ReplaceAll(serverConfigFile, "$CLIENT_PUBLIC_KEY", clientPublicKey)
	serverConfigFile = strings.ReplaceAll(serverConfigFile, "$CLIENT_INTERNAL_IP", o.ClientInternalIP)

	_, err = o.remoteCommand(Command{Text: "cat > /etc/wireguard/wg0.conf", StdIn: strings.NewReader(serverConfigFile)})
	if err != nil {
		Fatalf("Error writing wg0.conf on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo chmod -R 600 /etc/wireguard/"})
	if err != nil {
		Fatalf("Error changing /etc/wireguard directory file permissions: %s", err)
	}

	clientConfigFile := `[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_INTERNAL_IP/32
DNS = $DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_ENDPOINT`

	clientConfigFile = strings.ReplaceAll(clientConfigFile, "$CLIENT_PRIVATE_KEY", clientPrivateKey)
	clientConfigFile = strings.ReplaceAll(clientConfigFile, "$CLIENT_INTERNAL_IP", o.ClientInternalIP)
	clientConfigFile = strings.ReplaceAll(clientConfigFile, "$DNS", o.DNS)
	clientConfigFile = strings.ReplaceAll(clientConfigFile, "$SERVER_PUBLIC_KEY", serverPublicKey)
	clientConfigFile = strings.ReplaceAll(clientConfigFile, "$SERVER_ENDPOINT", o.DropletIP+":51820")

	if err := WriteFile(wgConfFileName, []byte(clientConfigFile), 0600); err != nil {
		Fatalf("Error writing client Wireguard config file: %s", err)
	}

	// Enable IP forwarding
	_, err = o.remoteCommand(Command{Text: `echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf`})
	if err != nil {
		Fatalf("Error enabling IP forwarding on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo sysctl -p"})
	if err != nil {
		Fatalf("Error reloading sysctl on remote host: %s", err)
	}

	// Configure firewall rules
	_, err = o.remoteCommand(Command{Text: "sudo ufw allow 51820/udp"})
	if err != nil {
		Fatalf("Error allowing port 51820 via ufw on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo ufw allow 22/tcp"})
	if err != nil {
		Fatalf("Error allowing port 22 via ufw on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo ufw disable"})
	if err != nil {
		Fatalf("Error disabling ufw on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo ufw --force enable"})
	if err != nil {
		Fatalf("Error enabling ufw on remote host: %s", err)
	}

	// Enable the wireguard systemd service
	_, err = o.remoteCommand(Command{Text: "sudo systemctl enable wg-quick@wg0.service"})
	if err != nil {
		Fatalf("Error enabling wg-quick@wg0.service on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo systemctl start wg-quick@wg0.service"})
	if err != nil {
		Fatalf("Error starting wg-quick@wg0.service on remote host: %s", err)
	}

	// Get QR code for the client config file
	_, err = o.remoteCommand(Command{Text: "sudo apt install -y qrencode"})
	if err != nil {
		Fatalf("Error installing qrencode on remote host: %s", err)
	}

	qrCode, err := o.remoteCommand(Command{Text: "qrencode -t ansiutf8", StdIn: strings.NewReader(clientConfigFile)})
	if err != nil {
		Fatalf("Error generating QR code for Wireguard config on remote host: %s", err)
	}

	fullConfPath := filepath.Join(configDirectory(), wgConfFileName)
	wgQuickCommand := fmt.Sprintf("sudo wg-quick up %s", fullConfPath)

	copyToClipboard(wgQuickCommand)
	fmt.Printf("\nSuccess! Run `sudo wg-quick up %s` to connect (copied to clipboard), or scan the following QR code:\n\n%s", fullConfPath, qrCode)
}

func (o *Orchestrator) destroyVMs() {
	log.Println("Destroying all ephemeral VMs")

	_, err := o.Client.Droplets.DeleteByTag(context.TODO(), dropletTagName)
	if err != nil {
		Fatalf("Error deleting all ephemeral VMs: %s\n\n", err)
	}

	o.deleteKnownhostsFile()
	o.deleteWgConfFile()
}

func (o *Orchestrator) deleteKnownhostsFile() error {
	return os.Remove(filepath.Join(configDirectory(), knownHostsFileName))
}
func (o *Orchestrator) deleteWgConfFile() error {
	return os.Remove(filepath.Join(configDirectory(), wgConfFileName))
}

func (o *Orchestrator) removeSSHKeysFromAccount() error {
	log.Println("Removing all ephemeral SSH keys from account")

	keys, _, err := o.Client.Keys.List(context.TODO(), &godo.ListOptions{})
	if err != nil {
		return err
	}

	for _, key := range keys {
		if key.Name == sshKeyName {
			_, err := o.Client.Keys.DeleteByID(context.TODO(), key.ID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *Orchestrator) confirmDeletionOfCurrentDroplets() {
	dropletCount, err := o.dropletsOnAccount()
	if err != nil {
		Fatalf("Error fetching current droplets from account: %s", err)
	}

	if dropletCount > 0 {
		reader := bufio.NewReader(os.Stdin)

		fmt.Printf("\nYou have %d `%s` tagged droplet on your account that will be deleted. Would you like to proceed? [y/n]: ", dropletCount, dropletTagName)

		response, err := reader.ReadString('\n')
		if err != nil {
			Fatalf("Error reading y/n prompt answer: %s", err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response != "y" && response != "yes" {
			fmt.Printf("\n")
			os.Exit(0)
		} else {
			fmt.Printf("\n")
		}
	}
}

func (o *Orchestrator) runSSH(ctx context.Context) error {
	key, err := ssh.ParsePrivateKey(o.SSHPrivateKey)
	if err != nil {
		return err
	}

	validateHostKeyCallback, err := knownhosts.New(filepath.Join(configDirectory(), knownHostsFileName))
	if err != nil {
		Fatalf("Could not create validateHostKeyCallback function: %s", err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: validateHostKeyCallback,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}

	hostport := fmt.Sprintf("%s:%d", o.DropletIP, 22)
	conn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		return fmt.Errorf("cannot connect %v: %v", hostport, err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open new session: %v", err)
	}
	defer session.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal make raw: %s", err)
	}
	defer term.Restore(fd, state)

	w, h, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("terminal get size: %s", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", h, w, modes); err != nil {
		return fmt.Errorf("session xterm: %s", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Shell(); err != nil {
		return fmt.Errorf("session shell: %s", err)
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		return fmt.Errorf("ssh: %s", err)
	}
	return nil

}

func (o *Orchestrator) runTCPLogger(port string) {
	targetFilePath := "/root/listen.py"

	intSig := make(chan os.Signal, 1)
	gracefulShutdown := false
	signal.Notify(intSig, os.Interrupt)

	go func() {
		<-intSig
		gracefulShutdown = true
		fmt.Println("\nShutting down remote services...")
		cleanup := fmt.Sprintf(`sudo ufw delete allow %s/tcp ; pkill -f "^./cloudflared" ; pkill -f "^python3 %s"`, port, targetFilePath)
		_, _ = o.remoteCommand(Command{Text: cleanup})
	}()

	scriptBytes, err := pythonScript.ReadFile("listen.py")
	if err != nil {
		Fatalf("Error reading embedded Python script: %s", err)
	}
	socketListenPythonScript := strings.ReplaceAll(string(scriptBytes), "$PORT", port)

	ufwAllowCommand := fmt.Sprintf("sudo ufw allow %s/tcp", port)
	_, err = o.remoteCommand(Command{Text: ufwAllowCommand})
	if err != nil {
		Fatalf("Error allowing port %s via ufw on remote host: %s", port, err)
	}

	writePythonFileCommand := fmt.Sprintf("cat > %s", targetFilePath)
	_, err = o.remoteCommand(Command{Text: writePythonFileCommand, StdIn: strings.NewReader(socketListenPythonScript)})
	if err != nil {
		Fatalf("Error writing %s on remote host: %s", targetFilePath, err)
	}

	stopPythonService := fmt.Sprintf(`pkill -f "^python3 %s"`, targetFilePath)
	_, _ = o.remoteCommand(Command{Text: stopPythonService})

	runServerCommand := fmt.Sprintf("python3 %s", targetFilePath)
	_, err = o.remoteCommand(Command{Text: runServerCommand, StdOut: os.Stdout, StdErr: os.Stderr, StdIn: os.Stdin})
	if err != nil {
		if !gracefulShutdown {
			Fatalf("Error running %s on remote host: %s", targetFilePath, err)
		}
	}
}

func (o *Orchestrator) startCloudflareTunnel(port string) {
	_, _ = o.remoteCommand(Command{Text: `pkill -f "^./cloudflared"`})

	downloadCommand := `wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared && chmod +x cloudflared`
	_, err := o.remoteCommand(Command{Text: downloadCommand})
	if err != nil {
		Fatalf("Error downloading cloudflared on remote host: %s", err)
	}

	var outBuffer bytes.Buffer
	done := make(chan struct{})

	go func() {
		pattern := `(https://.*\.trycloudflare\.com)`
		re := regexp.MustCompile(pattern)

		for {
			select {
			case <-done:
				return
			default:
				matches := re.FindStringSubmatch(outBuffer.String())

				if len(matches) > 0 {
					fmt.Printf("Accessible at: %s\n", matches[1])
					copyToClipboard(matches[1])
					close(done)
					return
				}

				time.Sleep(200 * time.Millisecond)
			}
		}
	}()

	go func() {
		runTunnelCommand := fmt.Sprintf("./cloudflared tunnel --url localhost:%s", port)
		_, err = o.remoteCommand(Command{Text: runTunnelCommand, StdOut: &outBuffer, StdErr: &outBuffer})
		if err != nil {
			Fatalf("Error running cloudflare tunnel on port %s: %s", port, err)
		}
	}()

	<-done
}

func (o *Orchestrator) performFullCleanup() {

	if o.Client != nil {
		fmt.Printf("Deleting SSH keys from your DigitalOcean account associated with this tooling\n")
		o.removeSSHKeysFromAccount()
		fmt.Printf("Destroying droplets from your DigitalOcean account associated with this tooling\n")
		o.destroyVMs()
		fmt.Printf("Cleanup complete. If the API key you supplied this tooling is no longer needed, revoke it at: https://cloud.digitalocean.com/account/api/tokens\n")
	}
	for key := range validKeyChainServiceKeys {
		fmt.Printf("Deleting keychain item '%s'\n", key)
		clearKeychainKey(key)
	}
	fmt.Printf("Deleting directory '%s'\n\n", configDirectory())
	os.RemoveAll(configDirectory())
}
