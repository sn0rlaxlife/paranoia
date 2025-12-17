package reports

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateHTMLReport(t *testing.T) {
	title := "Test Security Report"
	findings := []string{
		"Finding 1: Privileged pod detected",
		"Finding 2: No resource limits",
	}
	outputPath := "test-report.html"

	defer os.Remove(outputPath)

	err := GenerateHTMLReport(title, findings, outputPath)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(outputPath)
	assert.NoError(t, err)

	// Read and verify content
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, title)
	assert.Contains(t, contentStr, "Finding 1")
	assert.Contains(t, contentStr, "Finding 2")
	assert.Contains(t, contentStr, "<html>")
	assert.Contains(t, contentStr, "</html>")
}

func TestGenerateHTMLReportEmptyFindings(t *testing.T) {
	title := "Empty Report"
	findings := []string{}
	outputPath := "empty-report.html"

	defer os.Remove(outputPath)

	err := GenerateHTMLReport(title, findings, outputPath)
	require.NoError(t, err)

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	assert.Contains(t, string(content), title)
}
