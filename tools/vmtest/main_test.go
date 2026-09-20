package main

import "testing"

func TestManifestRejectsUnpinnedOrAmbiguousImages(t *testing.T) {
	valid := manifest{SchemaVersion: manifestSchema, Images: []image{{ID: "debian-13", Platform: "debian-13", SourceURL: "https://example.invalid/debian.qcow2", Checksum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ChecksumAlgorithm: "sha256", Verification: "official pinned checksum", Format: "qcow2", Provisioner: "cloud-init", User: "bebop", SudoGroup: "sudo", ExpectedInit: "systemd"}}}
	if err := validateManifest(valid); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	valid.Images[0].Checksum = ""
	if err := validateManifest(valid); err == nil {
		t.Fatal("manifest accepted unpinned image")
	}
	valid.Images[0].Checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid.Images = append(valid.Images, valid.Images[0])
	if err := validateManifest(valid); err == nil {
		t.Fatal("manifest accepted duplicate image identity")
	}
	valid.Images = valid.Images[:1]
	valid.Images[0].SourceURL = "https://example.invalid/latest/debian.qcow2"
	if err := validateManifest(valid); err == nil {
		t.Fatal("manifest accepted mutable latest URL")
	}
}
