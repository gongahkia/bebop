// Package facts contains normalized, transport-independent target observations.
package facts

type HostFacts struct {
	Target              string           `json:"target"`
	Hostname            string           `json:"hostname"`
	OS                  OS               `json:"os"`
	Architecture        string           `json:"architecture"`
	ArchitectureKnown   bool             `json:"architecture_known"`
	Kernel              string           `json:"kernel"`
	PackageManager      string           `json:"package_manager"`
	InitSystem          string           `json:"init_system"`
	Systemd             bool             `json:"systemd"`
	EffectiveUser       string           `json:"effective_user"`
	SudoAvailable       bool             `json:"sudo_available"`
	SSH                 SSH              `json:"ssh"`
	Docker              Docker           `json:"docker"`
	Tailscale           Tailscale        `json:"tailscale"`
	AutomaticUpdates    AutomaticUpdates `json:"automatic_updates"`
	Firewall            Firewall         `json:"firewall"`
	MemoryKiB           int64            `json:"memory_kib"`
	RootFilesystem      Filesystem       `json:"root_filesystem"`
	UnconfiguredStorage []StorageDevice  `json:"unconfigured_storage,omitempty"`
	DataRoot            Directory        `json:"data_root"`
}

type OS struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	VersionID       string `json:"version_id"`
	VersionCodename string `json:"version_codename"`
	Family          string `json:"family"`
	Supported       bool   `json:"supported"`
}

func (o OS) Display() string {
	if o.Name == "" {
		return o.ID
	}
	if o.VersionID == "" {
		return o.Name
	}
	return o.Name + " " + o.VersionID
}

type SSH struct {
	Installed             bool   `json:"installed"`
	Service               string `json:"service"`
	ServiceEnabled        bool   `json:"service_enabled"`
	ServiceActive         bool   `json:"service_active"`
	ConfigValid           bool   `json:"config_valid"`
	DropInSupported       bool   `json:"drop_in_supported"`
	AuthorizedKeysPresent bool   `json:"authorized_keys_present"`
	BebopDropIn           string `json:"bebop_drop_in,omitempty"`
}

type Docker struct {
	Installed      bool `json:"installed"`
	ServiceEnabled bool `json:"service_enabled"`
	ServiceActive  bool `json:"service_active"`
	Responsive     bool `json:"responsive"`
}

type Tailscale struct {
	Installed      bool   `json:"installed"`
	ServiceEnabled bool   `json:"service_enabled"`
	ServiceActive  bool   `json:"service_active"`
	Connected      bool   `json:"connected"`
	BackendState   string `json:"backend_state,omitempty"`
}

type AutomaticUpdates struct {
	Installed bool `json:"installed"`
	Enabled   bool `json:"enabled"`
}

type Firewall struct {
	UFWAvailable bool `json:"ufw_available"`
	UFWActive    bool `json:"ufw_active"`
	OtherActive  bool `json:"other_active"`
}

type Filesystem struct {
	Source       string `json:"source,omitempty"`
	Type         string `json:"type,omitempty"`
	SizeKiB      int64  `json:"size_kib,omitempty"`
	AvailableKiB int64  `json:"available_kib,omitempty"`
}

// StorageDevice is inspection-only. M0/M1 never creates a plan action from it.
type StorageDevice struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Transport string `json:"transport,omitempty"`
}

type Directory struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Mode     string `json:"mode,omitempty"`
	UID      int    `json:"uid,omitempty"`
	GID      int    `json:"gid,omitempty"`
	Writable bool   `json:"writable"`
}
