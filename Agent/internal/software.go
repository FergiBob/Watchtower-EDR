package internal

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"Watchtower_EDR/shared"

	"golang.org/x/sys/windows/registry"
)

// collectSoftwareData detects the OS and returns a slice of all found software
func CollectSoftwareData() ([]shared.Software, error) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsExhaustive()
	case "linux":
		return getLinuxExhaustive()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// --- Windows Implementation ---

func getWindowsExhaustive() ([]shared.Software, error) {
	sources := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	softwareMap := make(map[string]shared.Software)

	for _, source := range sources {
		list, err := vistedRegistryPath(source.root, source.path)
		if err != nil {
			continue
		}
		for _, s := range list {
			// Deduplicate by Name
			if _, exists := softwareMap[s.Name]; !exists {
				softwareMap[s.Name] = s
			}
		}
	}

	var results []shared.Software
	for _, s := range softwareMap {
		results = append(results, s)
	}
	return results, nil
}

func vistedRegistryPath(root registry.Key, path string) ([]shared.Software, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	var results []shared.Software
	for _, sk := range subkeys {
		subKeyPath := path + `\` + sk
		s, err := getSoftwareDetailsWin(root, subKeyPath)
		if err == nil && s.Name != "" {
			results = append(results, s)
		}
	}
	return results, nil
}

func getSoftwareDetailsWin(root registry.Key, path string) (shared.Software, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return shared.Software{}, err
	}
	defer k.Close()

	name, _, _ := k.GetStringValue("DisplayName")
	version, _, _ := k.GetStringValue("DisplayVersion")
	publisher, _, _ := k.GetStringValue("Publisher")
	date, _, _ := k.GetStringValue("InstallDate") // Format: YYYYMMDD

	return shared.Software{
		Name:         name,
		Version:      version,
		Manufacturer: publisher,
		Date:         date,
	}, nil
}

// --- Linux Implementation ---

func getLinuxExhaustive() ([]shared.Software, error) {
	var results []shared.Software

	// Debian/Ubuntu (dpkg doesn't track exact install date easily,
	// so we use the status file's last modify or omit if not critical)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, _ := exec.Command("dpkg-query", "-W", "-f=${Package};${Version};${Maintainer}\n").Output()
		results = append(results, parseLinuxOutput(string(out))...)
	}

	// RedHat/Fedora (RPM handles install time natively)
	if _, err := exec.LookPath("rpm"); err == nil {
		out, _ := exec.Command("rpm", "-qa", "--queryformat", "%{NAME};%{VERSION};%{VENDOR};%{INSTALLTIME:date}\n").Output()
		results = append(results, parseLinuxOutput(string(out))...)
	}

	return results, nil
}

func parseLinuxOutput(output string) []shared.Software {
	var list []shared.Software
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Split(line, ";")
		if len(parts) >= 3 {
			s := shared.Software{
				Name:         parts[0],
				Version:      parts[1],
				Manufacturer: parts[2],
			}
			if len(parts) == 4 {
				s.Date = parts[3]
			}
			list = append(list, s)
		}
	}
	return list
}
