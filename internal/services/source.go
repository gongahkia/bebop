// Package services owns controller-side Compose source validation and
// deterministic deployment inputs. It never executes a Compose project.
package services

import (
	"archive/tar"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"gopkg.in/yaml.v3"
)

const (
	SecretEnvName         = ".bebop-secret.env"
	SecretFingerprintName = ".bebop-secret-fingerprint"
	maxFiles              = 10_000
	maxBytes              = 256 << 20
)

var composeNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// File is one non-secret file in canonical logical deployment content.
// Mode preserves only the executable bit; unrelated controller permissions do
// not change desired service content.
type File struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

// Port is a declared fixed host-port mapping. It is deliberately a narrow
// static check, not a replacement for Docker Compose's full parser.
type Port struct {
	Binding string `json:"binding"`
}

// Deployment is resolved controller-only input. Payload and Secret are never
// serialized into a plan, artifact, report, or history record.
type Deployment struct {
	Name              string
	Project           string
	State             string
	ComposeFile       string
	SourceDirectory   string
	Files             []File
	SourceDigest      string
	SecretFingerprint string
	InputFingerprint  string
	SecretConfigured  bool
	Ports             []Port
	Payload           []byte
}

// Input is the persistent, non-secret portion of a resolved deployment. A
// keyed HMAC detects secret rotation without exposing a low-entropy digest.
type Input struct {
	Name              string `json:"name"`
	Project           string `json:"project"`
	State             string `json:"state"`
	SourceDigest      string `json:"source_digest,omitempty"`
	InputFingerprint  string `json:"input_fingerprint,omitempty"`
	SecretConfigured  bool   `json:"secret_configured,omitempty"`
	SecretFingerprint string `json:"secret_fingerprint,omitempty"`
}

func (deployment Deployment) Input() Input {
	return Input{
		Name: deployment.Name, Project: deployment.Project, State: deployment.State,
		SourceDigest: deployment.SourceDigest, InputFingerprint: deployment.InputFingerprint,
		SecretConfigured: deployment.SecretConfigured, SecretFingerprint: deployment.SecretFingerprint,
	}
}

// ResolveAll validates all active/stopped service sources before any target
// operation. Absent services intentionally do not require a controller source:
// a user may remove it locally while safely removing only the remote deployment.
func ResolveAll(cfg config.Config) ([]Deployment, error) {
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	deployments := make([]Deployment, 0, len(cfg.Services))
	bindings := map[string]string{}
	for _, service := range cfg.Services {
		deployment, err := resolveOne(cfg, service)
		if err != nil {
			return nil, err
		}
		for _, port := range deployment.Ports {
			if previous, exists := bindings[port.Binding]; exists {
				return nil, errs.New(errs.ConfigInvalid, fmt.Sprintf("services %q and %q both declare host port %s", previous, service.Name, port.Binding), nil)
			}
			bindings[port.Binding] = service.Name
		}
		deployments = append(deployments, deployment)
	}
	return deployments, nil
}

// ResolveOne is used by apply to re-read the controller input immediately
// before mutation. The module compares InputFingerprint with the reviewed plan
// so an edited source or rotated secret cannot silently be deployed.
func ResolveOne(cfg config.Config, name string) (Deployment, error) {
	if err := config.Validate(cfg); err != nil {
		return Deployment{}, err
	}
	for _, service := range cfg.Services {
		if service.Name == name {
			return resolveOne(cfg, service)
		}
	}
	return Deployment{}, errs.New(errs.ConfigInvalid, "unknown configured service "+name, nil)
}

func resolveOne(cfg config.Config, service config.Service) (Deployment, error) {
	deployment := Deployment{Name: service.Name, Project: ProjectName(cfg.Server.Name, service.Name), State: service.State}
	if service.State == "absent" {
		return deployment, nil
	}
	base, err := configurationDirectory(cfg)
	if err != nil {
		return Deployment{}, err
	}
	source, err := containedPath(base, service.Source)
	if err != nil {
		return Deployment{}, errs.New(errs.ConfigInvalid, "resolve service."+service.Name+".source", err)
	}
	files, composeFile, sourceDigest, sourceBytes, err := manifest(source)
	if err != nil {
		return Deployment{}, errs.New(errs.ConfigInvalid, "service."+service.Name+" source is unsafe", err)
	}
	ports, err := validateCompose(filepath.Join(source, filepath.FromSlash(composeFile)), files, service.SecretEnvFile != "")
	if err != nil {
		return Deployment{}, errs.New(errs.ConfigInvalid, "service."+service.Name+" Compose source is unsupported", err)
	}
	deployment.SourceDirectory, deployment.Files, deployment.ComposeFile = source, files, composeFile
	deployment.SourceDigest = sourceDigest
	deployment.Ports = ports
	secret := []byte(nil)
	if service.SecretEnvFile != "" {
		secretPath, pathErr := containedPath(base, service.SecretEnvFile)
		if pathErr != nil {
			return Deployment{}, errs.New(errs.ConfigInvalid, "resolve service."+service.Name+".secret_env_file", pathErr)
		}
		secret, pathErr = readRegularFile(secretPath, true)
		if pathErr != nil {
			return Deployment{}, errs.New(errs.ConfigInvalid, "read service."+service.Name+".secret_env_file", pathErr)
		}
		key, keyErr := secretKey(base)
		if keyErr != nil {
			return Deployment{}, keyErr
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(secret)
		deployment.SecretFingerprint = hex.EncodeToString(mac.Sum(nil))
		deployment.SecretConfigured = true
	}
	deployment.InputFingerprint = inputFingerprint(deployment.SourceDigest, deployment.SecretFingerprint)
	payload, err := archivePayload(source, files, secret, deployment.SecretFingerprint)
	if err != nil {
		return Deployment{}, err
	}
	deployment.Payload = payload
	if sourceBytes == 0 {
		return Deployment{}, fmt.Errorf("Compose source has no files")
	}
	return deployment, nil
}

// InputsFingerprint is a stable semantic digest for saved-plan validation. It
// includes source content and keyed secret state, but never content bytes.
func InputsFingerprint(cfg config.Config) (string, []Input, error) {
	deployments, err := ResolveAll(cfg)
	if err != nil {
		return "", nil, err
	}
	inputs := make([]Input, 0, len(deployments))
	for _, deployment := range deployments {
		inputs = append(inputs, deployment.Input())
	}
	fingerprint, err := FingerprintInputs(inputs)
	if err != nil {
		return "", nil, err
	}
	return fingerprint, inputs, nil
}

// FingerprintInputs validates the persistent representation without reading
// source files. Artifact decoding uses it to detect malformed/tampered input
// metadata before any local or target action.
func FingerprintInputs(inputs []Input) (string, error) {
	copyInputs := make([]Input, len(inputs))
	copy(copyInputs, inputs)
	sort.Slice(copyInputs, func(i, j int) bool { return copyInputs[i].Name < copyInputs[j].Name })
	for index, input := range copyInputs {
		if input.Name == "" || (index > 0 && input.Name == copyInputs[index-1].Name) || input.Project == "" || input.State == "" {
			return "", fmt.Errorf("invalid service input metadata")
		}
	}
	encoded, err := json.Marshal(copyInputs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ProjectName has no ambient hostname, target, or controller path input. The
// bounded hash avoids collisions after sanitizing a human server name.
func ProjectName(serverName, serviceName string) string {
	clean := strings.ToLower(serverName)
	clean = strings.Map(func(character rune) rune {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			return character
		}
		return '-'
	}, clean)
	clean = strings.Trim(clean, "-")
	if clean == "" {
		clean = "host"
	}
	seed := serverName + "\x00" + serviceName
	sum := sha256.Sum256([]byte(seed))
	return "bebop-" + truncate(clean, 24) + "-" + truncate(serviceName, 20) + "-" + hex.EncodeToString(sum[:])[:10]
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func configurationDirectory(cfg config.Config) (string, error) {
	if cfg.SourceDirectory() == "" {
		return "", fmt.Errorf("service configuration must be loaded from a file so source paths have a declaration directory")
	}
	base, err := filepath.EvalSymlinks(cfg.SourceDirectory())
	if err != nil {
		return "", fmt.Errorf("resolve configuration directory: %w", err)
	}
	info, err := os.Stat(base)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("configuration directory is not a directory")
	}
	return base, nil
}

func containedPath(base, relative string) (string, error) {
	if err := config.ValidateControllerRelativePath(relative, false); err != nil {
		return "", err
	}
	candidate := filepath.Join(base, filepath.FromSlash(strings.ReplaceAll(relative, "\\", "/")))
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	relativeToBase, err := filepath.Rel(base, resolved)
	if err != nil || relativeToBase == ".." || strings.HasPrefix(relativeToBase, ".."+string(filepath.Separator)) || filepath.IsAbs(relativeToBase) {
		return "", fmt.Errorf("path escapes the configuration directory")
	}
	return resolved, nil
}

func manifest(root string) ([]File, string, string, int64, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, "", "", 0, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, "", "", 0, fmt.Errorf("source must be a real directory")
	}
	files := make([]File, 0)
	var total int64
	compose := ""
	err = filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == root {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		logical := filepath.ToSlash(relative)
		if strings.ContainsRune(logical, '\n') || strings.ContainsRune(logical, '\x00') {
			return fmt.Errorf("path %q contains an unsupported control character", logical)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link %q is not allowed in a deployment source", logical)
		}
		if entry.IsDir() {
			if logical == ".git" || logical == "node_modules" {
				return fmt.Errorf("directory %q is excluded from deployment sources", logical)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special file %q is not allowed in a deployment source", logical)
		}
		if logical == SecretEnvName || logical == SecretFingerprintName {
			return fmt.Errorf("source may not contain reserved file %q", logical)
		}
		contents, err := readRegularFile(filename, false)
		if err != nil {
			return err
		}
		total += int64(len(contents))
		if total > maxBytes {
			return fmt.Errorf("source exceeds the %d MiB deployment limit", maxBytes>>20)
		}
		mode := "644"
		if info.Mode()&0o111 != 0 {
			mode = "755"
		}
		sum := sha256.Sum256(contents)
		files = append(files, File{Path: logical, Mode: mode, Digest: hex.EncodeToString(sum[:]), Bytes: int64(len(contents))})
		if filepath.Dir(logical) == "." {
			for _, candidate := range composeNames {
				if logical == candidate {
					if compose != "" {
						return fmt.Errorf("multiple Compose files found (%s and %s)", compose, logical)
					}
					compose = logical
				}
			}
		}
		if len(files) > maxFiles {
			return fmt.Errorf("source exceeds the %d-file deployment limit", maxFiles)
		}
		return nil
	})
	if err != nil {
		return nil, "", "", 0, err
	}
	if compose == "" {
		return nil, "", "", 0, fmt.Errorf("source must contain exactly one of %s", strings.Join(composeNames, ", "))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var canonical strings.Builder
	for _, file := range files {
		fmt.Fprintf(&canonical, "%s\t%s\t%s\n", file.Mode, file.Digest, file.Path)
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	return files, compose, hex.EncodeToString(sum[:]), total, nil
}

func readRegularFile(filename string, secret bool) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular non-symlink file")
	}
	if info.Size() > maxBytes || (secret && info.Size() > 1<<20) {
		return nil, fmt.Errorf("file is too large")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func inputFingerprint(source, secret string) string {
	sum := sha256.Sum256([]byte("source=" + source + "\nsecret=" + secret + "\n"))
	return hex.EncodeToString(sum[:])
}

func secretKey(base string) ([]byte, error) {
	directory := filepath.Join(base, ".bebop", "cache")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create local secret-fingerprint cache: %w", err)
	}
	filename := filepath.Join(directory, "secret-hmac.key")
	contents, err := os.ReadFile(filename)
	if err == nil {
		if len(contents) != 32 {
			return nil, fmt.Errorf("local secret-fingerprint key has invalid length; remove %s and re-plan", filename)
		}
		return contents, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return secretKey(base)
		}
		return nil, err
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func archivePayload(root string, files []File, secret []byte, secretFingerprint string) ([]byte, error) {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, file := range files {
		contents, err := readRegularFile(filepath.Join(root, filepath.FromSlash(file.Path)), false)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(contents)
		if hex.EncodeToString(sum[:]) != file.Digest {
			return nil, fmt.Errorf("source file %q changed while preparing deployment", file.Path)
		}
		mode, _ := strconv.ParseInt(file.Mode, 8, 64)
		header := &tar.Header{Name: file.Path, Mode: mode, Size: int64(len(contents)), Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(contents); err != nil {
			return nil, err
		}
	}
	if secret != nil {
		if err := writeArchiveFile(writer, SecretEnvName, 0o600, secret); err != nil {
			return nil, err
		}
		if err := writeArchiveFile(writer, SecretFingerprintName, 0o600, []byte(secretFingerprint+"\n")); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeArchiveFile(writer *tar.Writer, name string, mode int64, contents []byte) error {
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(contents)), Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	_, err := writer.Write(contents)
	return err
}

func validateCompose(filename string, files []File, secretConfigured bool) ([]Port, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, err
	}
	if containsAlias(&document) {
		return nil, fmt.Errorf("YAML aliases are not supported in managed Compose files")
	}
	root := document.Content
	if len(root) != 1 || root[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Compose document must be a mapping")
	}
	servicesNode := mappingValue(root[0], "services")
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode || len(servicesNode.Content) == 0 {
		return nil, fmt.Errorf("Compose document must declare at least one service")
	}
	fileSet := make(map[string]bool, len(files))
	for _, file := range files {
		fileSet[file.Path] = true
	}
	ports := make([]Port, 0)
	for index := 0; index < len(servicesNode.Content); index += 2 {
		serviceName, definition := servicesNode.Content[index], servicesNode.Content[index+1]
		if serviceName.Kind != yaml.ScalarNode || definition.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("Compose services must be named mappings")
		}
		if mappingValue(definition, "build") != nil {
			return nil, fmt.Errorf("service %q uses unsupported build; use an explicit image", serviceName.Value)
		}
		if mappingValue(definition, "profiles") != nil {
			return nil, fmt.Errorf("service %q uses unsupported profiles", serviceName.Value)
		}
		if mappingValue(definition, "extends") != nil {
			return nil, fmt.Errorf("service %q uses unsupported extends", serviceName.Value)
		}
		if err := validateEnvFiles(mappingValue(definition, "env_file"), fileSet, secretConfigured); err != nil {
			return nil, fmt.Errorf("service %q: %w", serviceName.Value, err)
		}
		if err := validateVolumes(mappingValue(definition, "volumes")); err != nil {
			return nil, fmt.Errorf("service %q: %w", serviceName.Value, err)
		}
		parsed, err := parsePorts(mappingValue(definition, "ports"))
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", serviceName.Value, err)
		}
		ports = append(ports, parsed...)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Binding < ports[j].Binding })
	return ports, nil
}

func containsAlias(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsAlias(child) {
			return true
		}
	}
	return false
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func validateEnvFiles(node *yaml.Node, sourceFiles map[string]bool, secretConfigured bool) error {
	if node == nil {
		return nil
	}
	values := []*yaml.Node{node}
	if node.Kind == yaml.SequenceNode {
		values = node.Content
	}
	for _, value := range values {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("env_file supports only relative string paths")
		}
		path := value.Value
		if path == SecretEnvName {
			if !secretConfigured {
				return fmt.Errorf("env_file %q requires service.secret_env_file", SecretEnvName)
			}
			continue
		}
		if err := config.ValidateControllerRelativePath(path, true); err != nil || !sourceFiles[path] {
			return fmt.Errorf("env_file %q must be a regular file inside the service source", path)
		}
	}
	return nil
}

// Releases are replaceable deployment content. A relative bind mount would
// make a service write persistent data below that replaceable tree, so M3
// requires named volumes or deliberate absolute target paths instead.
func validateVolumes(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("volumes must be a sequence")
	}
	for _, value := range node.Content {
		switch value.Kind {
		case yaml.ScalarNode:
			source, _, found := strings.Cut(value.Value, ":")
			if found && (source == "." || source == ".." || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")) {
				return fmt.Errorf("relative bind mount %q is unsafe; use a named volume or absolute target path", value.Value)
			}
		case yaml.MappingNode:
			typeNode := mappingValue(value, "type")
			if typeNode == nil || typeNode.Kind != yaml.ScalarNode || typeNode.Value != "bind" {
				continue
			}
			sourceNode := mappingValue(value, "source")
			if sourceNode == nil || sourceNode.Kind != yaml.ScalarNode || !strings.HasPrefix(sourceNode.Value, "/") {
				return fmt.Errorf("bind mounts require an absolute target source path")
			}
		default:
			return fmt.Errorf("volume must use string or long mapping syntax")
		}
	}
	return nil
}

func parsePorts(node *yaml.Node) ([]Port, error) {
	if node == nil {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("ports must be a sequence")
	}
	ports := make([]Port, 0)
	for _, value := range node.Content {
		binding, fixed, err := fixedPort(value)
		if err != nil {
			return nil, err
		}
		if fixed {
			ports = append(ports, Port{Binding: binding})
		}
	}
	return ports, nil
}

func fixedPort(node *yaml.Node) (string, bool, error) {
	if node.Kind == yaml.MappingNode {
		published := mappingValue(node, "published")
		if published == nil || (published.Kind != yaml.ScalarNode) {
			return "", false, fmt.Errorf("long port syntax requires scalar published")
		}
		protocol := "tcp"
		if value := mappingValue(node, "protocol"); value != nil && value.Kind == yaml.ScalarNode {
			protocol = strings.ToLower(value.Value)
		}
		hostIP := "0.0.0.0"
		if value := mappingValue(node, "host_ip"); value != nil && value.Kind == yaml.ScalarNode {
			hostIP = value.Value
		}
		return hostIP + ":" + published.Value + "/" + protocol, true, nil
	}
	if node.Kind != yaml.ScalarNode {
		return "", false, fmt.Errorf("port must use string or long mapping syntax")
	}
	value := node.Value
	protocol := "tcp"
	if before, after, found := strings.Cut(value, "/"); found {
		value, protocol = before, strings.ToLower(after)
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return "", false, nil // container port only
	}
	hostPort := parts[len(parts)-2]
	hostIP := "0.0.0.0"
	if len(parts) > 2 {
		hostIP = strings.Join(parts[:len(parts)-2], ":")
	}
	if hostPort == "" || strings.Contains(hostPort, "$") {
		return "", false, fmt.Errorf("published ports must be fixed values")
	}
	return hostIP + ":" + hostPort + "/" + protocol, true, nil
}
