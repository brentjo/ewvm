package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const usage = `Usage: ./ewvm <up | down | show | ssh | log | update | uninstall>
    up        - create Wireguard-enabled VM
    down      - destroy Wireguard-enabled VM
    show      - show Wireguard status via 'wg show' on the remote host
    ssh       - Interactive SSH into the remote host
    log       - Start TCP listener and print out traffic received
    update    - Update the remote host via apt upgrade
    uninstall - Delete all VMs, SSH keys, config directories, and keychain entries associated with this tooling
  
  Options:
      -r, --region     Region to create the VM for the 'up' command
      -d, --dns        DNS server to specify in the Wireguard config file for the 'up' command
      -i, --ip         Internal IP the remote VM will have on the Wireguard network for the 'up' command

      -p, --port       The port to listen for TCP connections on for the 'log' command
      -t, --tunnel     Use Cloudflare Tunnel for the 'log' command to expose the TCP listener on a public domain

  Examples:
    ewvm up --region sfo3 --ip 10.8.0.1
    ewvm log --port 80
    ewvm log --tunnel
`

func main() {
	if runtime.GOOS != "darwin" {
		fmt.Println("Tooling runs only on macOS for now")
		return
	}

	if len(os.Args[1:]) == 0 {
		fmt.Printf("\n%s\n", usage)
	} else if len(os.Args[1:]) >= 1 {
		action := os.Args[1]
		restOfArgs := os.Args[2:]

		logFile := setLogFile("ewvm.log")
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		defer logFile.Close()

		switch action {
		case "up":
			performUp(restOfArgs)
		case "down":
			performDown()
		case "show":
			performShow()
		case "ssh":
			performSSH()
		case "log":
			performLog(restOfArgs)
		case "uninstall":
			performUninstall()
		case "update":
			performUpdate()
		default:
			fmt.Printf("\n%s\n", usage)
		}
	} else {
		fmt.Printf("\n%s\n", usage)
	}
}

func performUp(args []string) {

	// Set up any optional command line options this command accepts
	var region string
	var serverIP string
	var dnsIP string

	fs := flag.NewFlagSet("up", flag.ExitOnError)
	fs.StringVar(&region, "r", "sfo3", "Region to deploy the VM")
	fs.StringVar(&region, "region", "sfo3", "Region to deploy the VM")
	fs.StringVar(&serverIP, "ip", "10.88.88.1", "Private IP for the remote host on the Wireguard network")
	fs.StringVar(&serverIP, "i", "10.88.88.1", "Private IP for the remote host on the Wireguard network")
	fs.StringVar(&dnsIP, "dns", "1.1.1.1", "DNS server to specify in the Wireguard configuration file")
	fs.StringVar(&dnsIP, "d", "1.1.1.1", "DNS server to specify in the Wireguard configuration file")

	fs.Parse(args)

	// Validate format of arguments
	if !validRegion(region) {
		fmt.Println("Invalid deployment region provided")
		os.Exit(1)
	}

	if !validServerIP(serverIP) {
		fmt.Println("Invalid IP")
		os.Exit(1)
	}

	if !validDNS(serverIP) {
		fmt.Println("Invalid IP")
		os.Exit(1)
	}

	log.Printf("Handling 'up' command with options region=%s, ip=%s, dns=%s\n", region, serverIP, dnsIP)

	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client:           apiClient,
		Region:           region,
		ServerInternalIP: serverIP,
		ClientInternalIP: clientIP(serverIP),
		DNS:              dnsIP,
	}

	o.confirmDeletionOfCurrentDroplets()

	o.removeSSHKeysFromAccount()
	o.destroyVMs()

	o.createSSHKey()

	fmt.Printf("Creating a VM in %s\n", o.Region)
	challenge := o.createVM()

	fmt.Println("VM booting...")
	o.pollUntilPublicIP()
	fmt.Printf("Assigned IP: %s\n", o.DropletIP)

	fmt.Println("Waiting for host to fully boot and initialize...")
	o.waitForHostToBoot()
	o.setupInitialSSHConnection(challenge)

	fmt.Println("Configuring Wireguard on the remote host...")
	o.configureWireguard()

	o.removeSSHKeysFromAccount()
}

func performDown() {
	log.Println("Handling 'down' command")

	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client: apiClient,
	}

	dropletCount, err := o.dropletsOnAccount()
	if err != nil {
		fmt.Println("Error fetching current droplets from account")
	}

	if dropletCount == 0 {
		o.removeSSHKeysFromAccount()
		fmt.Println("No VMs to destroy!")
	} else {
		o.confirmDeletionOfCurrentDroplets()
		o.removeSSHKeysFromAccount()
		o.destroyVMs()
	}
}

func performShow() {
	log.Println("Handling 'show' command")

	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client: apiClient,
	}

	o.setCurrentSSHKey()
	o.setCurrentDropletID()
	o.setCurrentDropletIP()

	output, err := o.remoteCommand(Command{Text: "wg show"})
	if err != nil {
		Fatalf("Error running 'wg show' on remote host: %s", err)
	}

	fmt.Println(output)
	os.Exit(0)
}

func performSSH() {
	log.Println("Handling 'ssh' command")

	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client: apiClient,
	}

	o.setCurrentSSHKey()
	o.setCurrentDropletID()
	o.setCurrentDropletIP()

	fmt.Printf("Starting interactive SSH into root@%s\n", o.DropletIP)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := o.runSSH(ctx); err != nil {
			log.Print(err)
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
	case <-ctx.Done():
	}
}

func performLog(args []string) {

	// Set up any optional command line options this command accepts
	var port int
	var tunnel bool

	fs := flag.NewFlagSet("log", flag.ExitOnError)
	fs.IntVar(&port, "p", 60001, "Port to listen for TCP connections on")
	fs.IntVar(&port, "port", 60001, "Port to listen for TCP connections on")
	fs.BoolVar(&tunnel, "tunnel", false, "Whether to serve from a domain (via Cloudflare tunnel) rather than raw IP")
	fs.BoolVar(&tunnel, "t", false, "Whether to serve from a domain (via Cloudflare tunnel) rather than raw IP")
	fs.Parse(args)

	// Validate format of arguments
	if !validPort(port) {
		fmt.Println("Invalid port provided")
		os.Exit(1)
	}

	log.Printf("Handling 'log' command with options port=%d\n", port)

	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client: apiClient,
	}

	o.setCurrentSSHKey()
	o.setCurrentDropletID()
	o.setCurrentDropletIP()

	fmt.Printf("Running TCP listen on %s:%d\n", o.DropletIP, port)

	if tunnel {
		o.startCloudflareTunnel(strconv.Itoa(port))
	}

	o.runTCPLogger(strconv.Itoa(port))
}

func performUpdate() {
	apiClient := validateOrPromptApiKeySetup()

	o := &Orchestrator{
		Client: apiClient,
	}

	o.setCurrentSSHKey()
	o.setCurrentDropletID()
	o.setCurrentDropletIP()

	_, err := o.remoteCommand(Command{Text: `sudo NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" upgrade`, StdOut: os.Stdout})
	if err != nil {
		Fatalf("Error running apt upgrade on remote host: %s", err)
	}

	_, err = o.remoteCommand(Command{Text: "sudo reboot"})
	if err != nil {
		Fatalf("Error running reboot on remote host: %s", err)
	}

	fmt.Println("\nVM rebooting...")
	time.Sleep(5 * time.Second)
	o.waitForHostToBoot()
	fmt.Println("Reboot complete!")
}

func performUninstall() {
	if hasValidApiKeyConfigured() {
		apiClient := validateOrPromptApiKeySetup()

		o := &Orchestrator{
			Client: apiClient,
		}

		o.performFullCleanup()
	} else {
		o := &Orchestrator{}
		o.performFullCleanup()
		fmt.Printf("No valid API token is currently configured, so no resources on your DigitalOcean account were cleaned up as part of this uninstall. Please manually cleanup any Droplets or SSH keys still on your account\n\nhttps://cloud.digitalocean.com/account/security\nhttps://cloud.digitalocean.com/droplets\n\n")
		fmt.Println("If you had previously ran 'ewvm down' after bringing any VMs up, you will not have any resources to clean up")
	}
}
