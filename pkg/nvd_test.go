package helpers

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestExtractCWE(t *testing.T) {
	testDataRaw, _ := ioutil.ReadFile("testdata/cwe.json")
	var allCVEs []CVEs
	var cve CVE
	json.Unmarshal(testDataRaw, &cve)
	expected := make([][]string, 3)
	expected[0] = []string{"CWE-200"}
	expected[1] = []string{}
	expected[2] = []string{"CWE-120", "CWE-190"}
	loadCVE(&allCVEs, &cve)
	for _, c := range cve.CVE_Items {

		t.Errorf("ProblemType: %s", c.CVE.ProblemType)
	}
}
