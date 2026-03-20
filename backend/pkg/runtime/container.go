package runtime

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const containerIDLength = 64

/*
GetContainerID extracts container runtime ID from /proc/<pid>/cgroup

Supported runtimes:
- containerd
- docker
- cri-o
- cri-containerd
*/
func GetContainerID(pid uint32) string {

	path := fmt.Sprintf("/proc/%d/cgroup", pid)

	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := scanner.Text()

		// important runtime filter
		if !(strings.Contains(line, "docker") ||
			strings.Contains(line, "containerd") ||
			strings.Contains(line, "cri-containerd") ||
			strings.Contains(line, "crio")) {
			continue
		}

		parts := strings.Split(line, "/")

		id := parts[len(parts)-1]

		id = normalizeContainerID(id)

		if isContainerID(id) {

			if len(id) > containerIDLength {
				id = id[len(id)-containerIDLength:]
			}

			return id
		}
	}

	return ""
}

/*
Check if string looks like a container ID

Container IDs are 64 hex characters
*/
func isContainerID(id string) bool {

	if len(id) < containerIDLength {
		return false
	}

	if len(id) > containerIDLength {
		id = id[len(id)-containerIDLength:]
	}

	for _, c := range id {

		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}
