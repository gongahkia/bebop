//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSSHInspectAgainstDisposableDebianAndUbuntu exercises Bebop's actual SSH
// transport. The containers intentionally do not run systemd, so this tier
// proves safe remote inspection and OS recognition rather than pretending to
// cover systemd-dependent apply behavior.
func TestSSHInspectAgainstDisposableDebianAndUbuntu(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	for _, command := range []string{"docker", "ssh-keygen"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is required for SSH integration: %v", command, err)
		}
	}
	binary := buildLinuxController(t)
	privateKey := integrationSSHKey(t)
	for _, fixture := range []struct {
		image string
		osID  string
	}{
		{image: "debian:12", osID: "debian"},
		{image: "ubuntu:24.04", osID: "ubuntu"},
	} {
		t.Run(fixture.osID, func(t *testing.T) {
			container := startSSHContainer(t, fixture.image, binary, privateKey)
			target := "ssh://bebop@127.0.0.1"
			// Run the controller inside the disposable target with a temporary
			// root-owned SSH config. This exercises Bebop's real external ssh
			// transport without reading or changing the developer's SSH files.
			controller := `install -d -m 0700 /root/.ssh
attempt=0
until command -v ssh-keyscan >/dev/null 2>&1 && ssh-keyscan -T 2 127.0.0.1 >/root/.ssh/known_hosts 2>/dev/null; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 180
  sleep 0.25
done
cat >/root/.ssh/config <<'EOF'
Host 127.0.0.1
  IdentityFile /controller/id_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile /root/.ssh/known_hosts
  StrictHostKeyChecking yes
EOF
exec /usr/local/bin/bebop inspect --target ssh://bebop@127.0.0.1 --json`
			command := exec.Command("docker", "exec", container, "sh", "-ceu", controller)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("inspect through actual SSH transport: %v\n%s", err, output)
			}
			var result struct {
				Target string `json:"target"`
				OS     struct {
					ID        string `json:"id"`
					Supported bool   `json:"supported"`
				} `json:"os"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode SSH inspect JSON: %v\n%s", err, output)
			}
			if result.Target != target || result.OS.ID != fixture.osID || !result.OS.Supported {
				t.Fatalf("unexpected remote SSH inspection: %#v", result)
			}
		})
	}
}

func buildLinuxController(t *testing.T) string {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "bebop")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bebop")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux controller: %v\n%s", err, output)
	}
	return binary
}

func integrationSSHKey(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(sshDirectory, "id_ed25519")
	if output, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privateKey).CombinedOutput(); err != nil {
		t.Fatalf("generate integration SSH key: %v\n%s", err, output)
	}
	return privateKey
}

func startSSHContainer(t *testing.T, image, binary, privateKey string) string {
	t.Helper()
	publicKey, err := os.ReadFile(privateKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	script := `export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openssh-server openssh-client
useradd -m -s /bin/sh bebop
install -d -m 0700 -o bebop -g bebop /home/bebop/.ssh
printf '%s\n' "$BEBOP_AUTHORIZED_KEY" >/home/bebop/.ssh/authorized_keys
chown bebop:bebop /home/bebop/.ssh/authorized_keys
chmod 0600 /home/bebop/.ssh/authorized_keys
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e`
	command := exec.Command("docker", "run", "--rm", "-d",
		"--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly",
		"--mount", "type=bind,src="+privateKey+",dst=/controller/id_ed25519,readonly",
		"-e", "BEBOP_AUTHORIZED_KEY="+strings.TrimSpace(string(publicKey)), image, "sh", "-ceu", script)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("start %s SSH target: %v\n%s", image, err, output)
	}
	container := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})
	return container
}
