package analysis

import "fmt"

func GetCWEInfo(pattern string) string {
	if info, found := CWEDetails[pattern]; found {
		return fmt.Sprintf("CWE: %s - %s", info.CWEID, info.Description)
	}
	return "No CWE information available."
}

