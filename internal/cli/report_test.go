package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/preflight"
)

func TestDoctorReportAddsPlatformFieldsWithoutReplacingExistingJSON(t *testing.T) {
	report := doctorReport(preflight.Result{Target: "local", Ready: true, Platform: "alpine-3.24", DetectedArch: "arm64", PackageManager: "apk", InitSystem: facts.InitSystemOpenRC, Checks: []preflight.Check{{Status: preflight.Pass, Code: "os.supported", Message: "supported"}}})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"\"target\":\"local\"", "\"ready\":true", "\"checks\"", "\"platform\":\"alpine-3.24\"", "\"architecture\":\"arm64\"", "\"package_manager\":\"apk\"", "\"init_system\":\"openrc\""} {
		if !strings.Contains(string(encoded), required) {
			t.Fatalf("doctor JSON omitted %s: %s", required, encoded)
		}
	}
}
