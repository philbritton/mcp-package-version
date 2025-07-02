package tests

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/philbritton/mcp-package-version/v2/internal/handlers"
	"github.com/sirupsen/logrus"
)

func TestDotNetHandler_GetLatestVersion(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	cache := &sync.Map{}
	
	// Create a mock client
	mockClient := NewMockClient()
	
	// Add mock response for Newtonsoft.Json using the helper function
	mockClient.AddNuGetPackageResponse("Newtonsoft.Json", "13.0.3", []string{"13.0.1", "13.0.2", "13.0.3"})
	
	// Create handler with mock client using the new constructor
	handler := handlers.NewDotNetHandlerWithClient(logger, cache, mockClient)
	
	// Test with valid dependencies
	args := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{
				"packageId": "Newtonsoft.Json",
				"version":   "12.0.3",
			},
		},
	}
	
	result, err := handler.GetLatestVersion(context.Background(), args)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	// Parse the result to check its structure
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result, got empty")
	}
	
	textContent, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("Expected text content in result, got %T", result.Content[0])
	}
	
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(textContent.Text), &resultData); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}
	
	packages, ok := resultData["packages"].([]interface{})
	if !ok {
		t.Fatal("Expected packages array in result")
	}
	
	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}
	
	pkg := packages[0].(map[string]interface{})
	if pkg["name"] != "Newtonsoft.Json" {
		t.Errorf("Expected package name 'Newtonsoft.Json', got %v", pkg["name"])
	}
	
	if pkg["latestVersion"] != "13.0.3" {
		t.Errorf("Expected latest version '13.0.3', got %v", pkg["latestVersion"])
	}
}

func TestDotNetHandler_PackageNotFound(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	cache := &sync.Map{}
	
	// Create a mock client
	mockClient := NewMockClient()
	
	// Mock response for package not found
	notFoundResponse := `{
		"data": [],
		"totalHits": 0
	}`
	
	mockClient.AddMockResponse(
		"azuresearch-usnc.nuget.org/query?q=NonExistentPackage",
		MockResponse{
			StatusCode: 200,
			Body:       notFoundResponse,
			Headers:    map[string]string{"Content-Type": "application/json"},
		},
	)
	
	// Create handler with mock client
	handler := handlers.NewDotNetHandlerWithClient(logger, cache, mockClient)
	
	// Test with non-existent package
	args := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{
				"packageId": "NonExistentPackage",
				"version":   "1.0.0",
			},
		},
	}
	
	result, err := handler.GetLatestVersion(context.Background(), args)
	
	// The handler should handle this gracefully and mark the package as skipped
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	// Parse the result
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result, got empty")
	}
	
	textContent, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("Expected text content in result, got %T", result.Content[0])
	}
	
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(textContent.Text), &resultData); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}
	
	packages, ok := resultData["packages"].([]interface{})
	if !ok {
		t.Fatal("Expected packages array in result")
	}
	
	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}
	
	pkg := packages[0].(map[string]interface{})
	if pkg["skipped"] != true {
		t.Errorf("Expected package to be skipped, got %v", pkg["skipped"])
	}
}

// Test the actual NuGet API to see what the real response looks like
func TestNuGetAPIResponse(t *testing.T) {
	t.Skip("This is for manual testing only - it makes real API calls")
	
	// This test can be used to understand the actual NuGet API response structure
	// Run with: go test -v -run TestNuGetAPIResponse
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	cache := &sync.Map{}
	handler := handlers.NewDotNetHandler(logger, cache)
	
	args := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{
				"packageId": "Newtonsoft.Json",
			},
		},
	}
	
	result, err := handler.GetLatestVersion(context.Background(), args)
	if err != nil {
		t.Logf("Error: %v", err)
	} else if len(result.Content) > 0 {
		if textContent, ok := result.Content[0].(mcp.TextContent); ok {
			t.Logf("Result: %s", textContent.Text)
		} else {
			t.Log("Result content is not text")
		}
	} else {
		t.Log("No content in result")
	}
}

func TestDotNetHandler_VersionConstraints(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	cache := &sync.Map{}
	
	// Create a mock client
	mockClient := NewMockClient()
	
	// Add mock response for a package with multiple versions
	mockClient.AddNuGetPackageResponse("Microsoft.Extensions.Logging", "8.0.2", []string{
		"6.0.0", "6.0.1", "6.0.2", 
		"7.0.0", "7.0.1", 
		"8.0.0", "8.0.1", "8.0.2",
	})
	
	// Create handler with mock client
	handler := handlers.NewDotNetHandlerWithClient(logger, cache, mockClient)
	
	// Test with major version constraint (only version 7.x)
	args := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{
				"packageId": "Microsoft.Extensions.Logging",
				"version":   "7.0.0",
			},
		},
		"constraints": map[string]interface{}{
			"Microsoft.Extensions.Logging": map[string]interface{}{
				"majorVersion": float64(7), // JSON numbers are float64
			},
		},
	}
	
	result, err := handler.GetLatestVersion(context.Background(), args)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	// Parse the result
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result, got empty")
	}
	
	textContent, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("Expected text content in result, got %T", result.Content[0])
	}
	
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(textContent.Text), &resultData); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}
	
	packages, ok := resultData["packages"].([]interface{})
	if !ok {
		t.Fatal("Expected packages array in result")
	}
	
	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}
	
	pkg := packages[0].(map[string]interface{})
	if pkg["name"] != "Microsoft.Extensions.Logging" {
		t.Errorf("Expected package name 'Microsoft.Extensions.Logging', got %v", pkg["name"])
	}
	
	// Should be the latest 7.x version (7.0.1), not the overall latest (8.0.2)
	if pkg["latestVersion"] != "7.0.1" {
		t.Errorf("Expected latest version with constraint '7.0.1', got %v", pkg["latestVersion"])
	}
	
	t.Logf("Result with constraints: %s", textContent.Text)
}

func TestDotNetHandler_ExcludePackage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	cache := &sync.Map{}
	
	// Create a mock client
	mockClient := NewMockClient()
	
	// Add mock response
	mockClient.AddNuGetPackageResponse("ExcludedPackage", "1.0.0", []string{"1.0.0"})
	
	// Create handler with mock client
	handler := handlers.NewDotNetHandlerWithClient(logger, cache, mockClient)
	
	// Test with exclude package constraint
	args := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{
				"packageId": "ExcludedPackage",
				"version":   "1.0.0",
			},
		},
		"constraints": map[string]interface{}{
			"ExcludedPackage": map[string]interface{}{
				"excludePackage": true,
			},
		},
	}
	
	result, err := handler.GetLatestVersion(context.Background(), args)
	
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	// Parse the result
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result, got empty")
	}
	
	textContent, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("Expected text content in result, got %T", result.Content[0])
	}
	
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(textContent.Text), &resultData); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}
	
	packages, ok := resultData["packages"].([]interface{})
	if !ok {
		t.Fatal("Expected packages array in result")
	}
	
	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}
	
	pkg := packages[0].(map[string]interface{})
	if pkg["skipped"] != true {
		t.Errorf("Expected package to be skipped, got %v", pkg["skipped"])
	}
	
	if pkg["skipReason"] != "excluded by constraint" {
		t.Errorf("Expected skip reason 'excluded by constraint', got %v", pkg["skipReason"])
	}
}