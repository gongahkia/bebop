// vmtest boots a reviewed cloud image under QEMU and exercises Bebop through
// its normal SSH transport. It is deliberately an opt-in test tool, not a
// controller feature or alternate target transport.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const manifestSchema = 1

type manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Images        []image `json:"images"`
}

type image struct {
	ID                string `json:"id"`
	Platform          string `json:"platform"`
	SourceURL         string `json:"source_url"`
	Checksum          string `json:"checksum"`
	ChecksumAlgorithm string `json:"checksum_algorithm"`
	Verification      string `json:"verification"`
	Format            string `json:"format"`
	Provisioner       string `json:"provisioner"`
	User              string `json:"user"`
	SudoGroup         string `json:"sudo_group"`
	ExpectedInit      string `json:"expected_init"`
}

func main() {
	var manifestPath, platform, cache string
	var allowTCG bool
	flag.StringVar(&manifestPath, "manifest", "testdata/vm/images.json", "reviewed VM image manifest")
	flag.StringVar(&platform, "platform", "", "one reviewed VM platform, or all")
	flag.StringVar(&cache, "cache", ".bebop/vm/images", "verified immutable image cache")
	flag.BoolVar(&allowTCG, "allow-tcg", false, "allow explicit software emulation when KVM is unavailable")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("unexpected arguments")
	}
	if err := run(context.Background(), manifestPath, platform, cache, allowTCG); err != nil {
		fatal(err.Error())
	}
}

func run(ctx context.Context, manifestPath, requested, cache string, allowTCG bool) error {
	for _, program := range []string{"qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh", "ssh-keygen", "go"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("VM harness prerequisite %q is unavailable: %w", program, err)
		}
	}
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var value manifest
	if err := json.Unmarshal(contents, &value); err != nil {
		return fmt.Errorf("decode image manifest: %w", err)
	}
	if err := validateManifest(value); err != nil {
		return err
	}
	images := selectImages(value.Images, requested)
	if len(images) == 0 {
		return fmt.Errorf("no reviewed VM image matches %q", requested)
	}
	if _, err := os.Stat("/dev/kvm"); err != nil && !allowTCG {
		return fmt.Errorf("/dev/kvm is unavailable; rerun with -allow-tcg only for explicitly accepted slow emulation")
	}
	for _, current := range images {
		if err := smoke(ctx, current, cache, allowTCG); err != nil {
			return fmt.Errorf("%s: %w", current.ID, err)
		}
	}
	return nil
}

func validateManifest(value manifest) error {
	if value.SchemaVersion != manifestSchema || len(value.Images) == 0 {
		return fmt.Errorf("invalid VM image manifest")
	}
	seen := map[string]bool{}
	for _, current := range value.Images {
		parsed, err := url.Parse(current.SourceURL)
		if current.ID == "" || seen[current.ID] || current.Platform == "" || err != nil || parsed.Scheme != "https" || parsed.Host == "" || strings.Contains("/"+parsed.Path+"/", "/latest/") || strings.Contains("/"+parsed.Path+"/", "/daily/") || current.Format != "qcow2" || current.Provisioner != "cloud-init" || current.User == "" || current.SudoGroup == "" || current.ExpectedInit == "" || current.Verification == "" {
			return fmt.Errorf("invalid VM image entry %q", current.ID)
		}
		seen[current.ID] = true
		length := 0
		switch current.ChecksumAlgorithm {
		case "sha256":
			length = sha256.Size * 2
		case "sha512":
			length = sha512.Size * 2
		default:
			return fmt.Errorf("unsupported checksum algorithm for %s", current.ID)
		}
		if len(current.Checksum) != length {
			return fmt.Errorf("invalid checksum length for %s", current.ID)
		}
		if _, err := hex.DecodeString(current.Checksum); err != nil {
			return fmt.Errorf("invalid checksum for %s", current.ID)
		}
	}
	return nil
}

func selectImages(images []image, requested string) []image {
	selected := make([]image, 0, len(images))
	for _, current := range images {
		if requested == "" || requested == "all" || requested == current.ID || requested == current.Platform {
			selected = append(selected, current)
		}
	}
	return selected
}

func smoke(parent context.Context, current image, cache string, allowTCG bool) error {
	ctx, cancel := context.WithTimeout(parent, 12*time.Minute)
	defer cancel()
	base, err := fetchVerified(ctx, current, cache)
	if err != nil {
		return err
	}
	runDir, err := os.MkdirTemp("", "bebop-vm-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runDir)
	base, err = filepath.Abs(base)
	if err != nil {
		return err
	}
	overlay := filepath.Join(runDir, "overlay.qcow2")
	if err := command(ctx, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay); err != nil {
		return err
	}
	privateKey := filepath.Join(runDir, "id_ed25519")
	if err := command(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privateKey); err != nil {
		return err
	}
	publicKey, err := os.ReadFile(privateKey + ".pub")
	if err != nil {
		return err
	}
	seed := filepath.Join(runDir, "seed.img")
	if err := writeSeed(ctx, runDir, seed, current.User, current.SudoGroup, strings.TrimSpace(string(publicKey))); err != nil {
		return err
	}
	port, err := freeLoopbackPort()
	if err != nil {
		return err
	}
	console := filepath.Join(runDir, "console.log")
	qemuArgs := []string{"-m", "2048", "-smp", "2", "-nographic", "-serial", "file:" + console, "-drive", "file=" + overlay + ",if=virtio,format=qcow2", "-drive", "file=" + seed + ",if=virtio,format=raw,readonly=on", "-netdev", fmt.Sprintf("user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22", port), "-device", "virtio-net-pci,netdev=n0"}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		qemuArgs = append([]string{"-enable-kvm"}, qemuArgs...)
	} else if !allowTCG {
		return errors.New("KVM disappeared before VM boot")
	}
	qemu := exec.CommandContext(ctx, "qemu-system-x86_64", qemuArgs...)
	if err := qemu.Start(); err != nil {
		return err
	}
	defer func() {
		if qemu.Process != nil {
			_ = qemu.Process.Kill()
		}
		_ = qemu.Wait()
	}()
	knownHosts := filepath.Join(runDir, "known_hosts")
	if err := waitSSH(ctx, privateKey, knownHosts, current.User, port); err != nil {
		return fmt.Errorf("wait for SSH (console retained at %s): %w", console, err)
	}
	binary := filepath.Join(runDir, "bebop")
	if err := command(ctx, "go", "build", "-o", binary, "./cmd/bebop"); err != nil {
		return err
	}
	sshDirectory := filepath.Join(runDir, ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		return err
	}
	sshConfig := "Host 127.0.0.1\n  IdentityFile " + privateKey + "\n  IdentitiesOnly yes\n  UserKnownHostsFile " + knownHosts + "\n  StrictHostKeyChecking yes\n"
	if err := os.WriteFile(filepath.Join(sshDirectory, "config"), []byte(sshConfig), 0o600); err != nil {
		return err
	}
	target := fmt.Sprintf("ssh://%s@127.0.0.1:%d", current.User, port)
	for _, subcommand := range []string{"inspect", "doctor", "status"} {
		if err := commandEnv(ctx, []string{"HOME=" + runDir}, binary, subcommand, "--target", target, "--json"); err != nil {
			return fmt.Errorf("bebop %s through SSH: %w", subcommand, err)
		}
	}
	return nil
}

func fetchVerified(ctx context.Context, current image, cache string) (string, error) {
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", err
	}
	filename := filepath.Join(cache, current.ID+".qcow2")
	if info, err := os.Lstat(filename); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		if err := verifyFile(filename, current); err == nil {
			return filename, nil
		}
		if err := os.Remove(filename); err != nil {
			return "", err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.SourceURL, nil)
	if err != nil {
		return "", err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", current.SourceURL, response.Status)
	}
	temporary, err := os.CreateTemp(cache, ".image-*")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := io.Copy(temporary, io.LimitReader(response.Body, 8<<30)); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := verifyFile(temporaryName, current); err != nil {
		return "", err
	}
	if err := os.Chmod(temporaryName, 0o400); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return "", err
	}
	return filename, nil
}

func verifyFile(filename string, current image) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	var actual string
	switch current.ChecksumAlgorithm {
	case "sha256":
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return err
		}
		actual = hex.EncodeToString(hash.Sum(nil))
	case "sha512":
		hash := sha512.New()
		if _, err := io.Copy(hash, file); err != nil {
			return err
		}
		actual = hex.EncodeToString(hash.Sum(nil))
	}
	if actual != current.Checksum {
		return fmt.Errorf("checksum mismatch for %s", current.ID)
	}
	return nil
}

func writeSeed(ctx context.Context, directory, seed, user, sudoGroup, key string) error {
	userData := "#cloud-config\nusers:\n  - default\n  - name: " + user + "\n    groups: [" + sudoGroup + "]\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/sh\n    ssh_authorized_keys:\n      - " + key + "\nssh_pwauth: false\n"
	metaData := "instance-id: bebop-vm\nlocal-hostname: bebop-vm\n"
	if err := os.WriteFile(filepath.Join(directory, "user-data"), []byte(userData), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "meta-data"), []byte(metaData), 0o600); err != nil {
		return err
	}
	return command(ctx, "cloud-localds", seed, filepath.Join(directory, "user-data"), filepath.Join(directory, "meta-data"))
}

func waitSSH(ctx context.Context, key, knownHosts, user string, port int) error {
	for {
		args := []string{"-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + knownHosts, "-p", fmt.Sprintf("%d", port), user + "@127.0.0.1", "true"}
		if err := command(ctx, "ssh", args...); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func command(ctx context.Context, program string, arguments ...string) error {
	return commandEnv(ctx, nil, program, arguments...)
}

func commandEnv(ctx context.Context, environment []string, program string, arguments ...string) error {
	value := exec.CommandContext(ctx, program, arguments...)
	value.Dir, _ = os.Getwd()
	value.Env = append(os.Environ(), environment...)
	output, err := value.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", program, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "vmtest:", message)
	os.Exit(1)
}
