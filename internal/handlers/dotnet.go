package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// NuGetRegistryURL is the base URL for the NuGet API
	NuGetRegistryURL = "https://api.nuget.org/v3"
	// NuGetSearchURL is the URL for searching packages
	NuGetSearchURL = "https://azuresearch-usnc.nuget.org/query"
)

// DotNetHandler handles .NET package version checking
type DotNetHandler struct {
	client HTTPClient
	cache  *sync.Map
	logger *logrus.Logger
}

// NewDotNetHandler creates a new DotNet handler
func NewDotNetHandler(logger *logrus.Logger, cache *sync.Map) *DotNetHandler {
	if cache == nil {
		cache = &sync.Map{}
	}
	return &DotNetHandler{
		client: DefaultHTTPClient,
		cache:  cache,
		logger: logger,
	}
}

// NewDotNetHandlerWithClient creates a new DotNet handler with a custom HTTP client
func NewDotNetHandlerWithClient(logger *logrus.Logger, cache *sync.Map, client HTTPClient) *DotNetHandler {
	if cache == nil {
		cache = &sync.Map{}
	}
	return &DotNetHandler{
		client: client,
		cache:  cache,
		logger: logger,
	}
}

// NuGetPackageInfo represents information about a NuGet package
type NuGetPackageInfo struct {
	Data []struct {
		ID          string `json:"id"`
		Version     string `json:"version"`
		Description string `json:"description"`
		Authors     []string `json:"authors"`
		Versions    []struct {
			Version string `json:"version"`
			ID      string `json:"@id"`
		} `json:"versions"`
	} `json:"data"`
	TotalHits int `json:"totalHits"`
}

// getPackageInfo gets information about a NuGet package
func (h *DotNetHandler) getPackageInfo(packageName string) (*NuGetPackageInfo, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("nuget:%s", packageName)
	if cachedInfo, ok := h.cache.Load(cacheKey); ok {
		h.logger.WithField("package", packageName).Debug("Using cached NuGet package info")
		return cachedInfo.(*NuGetPackageInfo), nil
	}

	// Construct URL for package search
	searchURL := fmt.Sprintf("%s?q=%s&prerelease=false&semVerLevel=2.0.0&take=1", NuGetSearchURL, packageName)
	h.logger.WithFields(logrus.Fields{
		"package": packageName,
		"url":     searchURL,
	}).Debug("Fetching NuGet package info")

	// Make request
	body, err := MakeRequestWithLogger(h.client, h.logger, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NuGet package info: %w", err)
	}

	// Parse response
	var info NuGetPackageInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse NuGet package info: %w", err)
	}

	// Check if package was found
	if len(info.Data) == 0 {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}

	// Cache result
	h.cache.Store(cacheKey, &info)

	return &info, nil
}

// getAvailableVersions extracts all available versions from package info
func (h *DotNetHandler) getAvailableVersions(packageInfo *NuGetPackageInfo) []string {
	if len(packageInfo.Data) == 0 {
		return []string{}
	}

	var versions []string
	
	// Add the current/latest version
	if packageInfo.Data[0].Version != "" {
		versions = append(versions, packageInfo.Data[0].Version)
	}
	
	// Add all versions from the versions array
	for _, versionInfo := range packageInfo.Data[0].Versions {
		if versionInfo.Version != "" {
			// Check if version is already added to avoid duplicates
			found := false
			for _, existing := range versions {
				if existing == versionInfo.Version {
					found = true
					break
				}
			}
			if !found {
				versions = append(versions, versionInfo.Version)
			}
		}
	}
	
	// Sort versions using proper version comparison
	sort.Slice(versions, func(i, j int) bool {
		if cmp, err := CompareVersions(versions[i], versions[j]); err == nil {
			return cmp < 0
		}
		// Fallback to string comparison if version parsing fails
		return versions[i] < versions[j]
	})
	
	return versions
}

// NuGetDependency represents a NuGet dependency in a .csproj file
type NuGetDependency struct {
	PackageID  string `json:"packageId"`
	Version    string `json:"version,omitempty"`
	IsDevDep   bool   `json:"isDevelopmentDependency,omitempty"`
	TargetFwrk string `json:"targetFramework,omitempty"`
}

// GetLatestVersion gets the latest version of NuGet packages
func (h *DotNetHandler) GetLatestVersion(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	h.logger.Debug("Getting latest NuGet package versions")

	// Parse dependencies
	depsRaw, ok := args["dependencies"]
	if !ok {
		return nil, fmt.Errorf("missing required parameter: dependencies")
	}

	// Convert to array of NuGetDependency objects
	var dependencies []NuGetDependency
	depsArray, ok := depsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("dependencies must be an array")
	}

	for _, depRaw := range depsArray {
		if dep, ok := depRaw.(map[string]interface{}); ok {
			var nugetDep NuGetDependency

			// Extract packageId
			if packageID, ok := dep["packageId"].(string); ok {
				nugetDep.PackageID = packageID
			} else {
				h.logger.WithField("package", dep).Warn("Invalid NuGet dependency: missing packageId")
				continue
			}

			// Extract version (optional)
			if version, ok := dep["version"].(string); ok {
				nugetDep.Version = version
			}

			// Extract isDevelopmentDependency (optional)
			if isDevDep, ok := dep["isDevelopmentDependency"].(bool); ok {
				nugetDep.IsDevDep = isDevDep
			}

			// Extract targetFramework (optional)
			if targetFwrk, ok := dep["targetFramework"].(string); ok {
				nugetDep.TargetFwrk = targetFwrk
			}

			dependencies = append(dependencies, nugetDep)
		}
	}

	// Parse constraints (optional)
	var constraints VersionConstraints
	if constraintsRaw, ok := args["constraints"]; ok {
		if constraintsMap, ok := constraintsRaw.(map[string]interface{}); ok {
			constraints = make(VersionConstraints)
			for name, constraintRaw := range constraintsMap {
				if constraint, ok := constraintRaw.(map[string]interface{}); ok {
					var versionConstraint VersionConstraint
					if majorVersionRaw, ok := constraint["majorVersion"]; ok {
						if majorVersion, ok := majorVersionRaw.(float64); ok {
							majorVersionInt := int(majorVersion)
							versionConstraint.MajorVersion = &majorVersionInt
						}
					}
					if excludePackageRaw, ok := constraint["excludePackage"]; ok {
						if excludePackage, ok := excludePackageRaw.(bool); ok {
							versionConstraint.ExcludePackage = excludePackage
						}
					}
					constraints[name] = versionConstraint
				}
			}
		}
	}

	// Get latest versions for all packages
	var result []PackageVersion
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, dep := range dependencies {
		wg.Add(1)
		go func(dep NuGetDependency) {
			defer wg.Done()

			packageName := dep.PackageID
			currentVersion := dep.Version

			// Check if package should be skipped based on constraints
			if constraint, ok := constraints[packageName]; ok && constraint.ExcludePackage {
				mu.Lock()
				result = append(result, PackageVersion{
					Name:           packageName,
					CurrentVersion: &currentVersion,
					LatestVersion:  currentVersion,
					Registry:       "nuget",
					Skipped:        true,
					SkipReason:     "excluded by constraint",
				})
				mu.Unlock()
				return
			}

			h.logger.WithFields(logrus.Fields{
				"package": packageName,
				"current": currentVersion,
			}).Debug("Checking NuGet package version")

			// Get package info
			packageInfo, err := h.getPackageInfo(packageName)
			if err != nil {
				h.logger.WithFields(logrus.Fields{
					"package": packageName,
					"error":   err.Error(),
				}).Warn("Failed to get NuGet package info")

				mu.Lock()
				result = append(result, PackageVersion{
					Name:           packageName,
					CurrentVersion: &currentVersion,
					LatestVersion:  currentVersion,
					Registry:       "nuget",
					Skipped:        true,
					SkipReason:     fmt.Sprintf("error: %s", err.Error()),
				})
				mu.Unlock()
				return
			}

			if len(packageInfo.Data) == 0 {
				h.logger.WithField("package", packageName).Warn("NuGet package not found")
				mu.Lock()
				result = append(result, PackageVersion{
					Name:           packageName,
					CurrentVersion: &currentVersion,
					LatestVersion:  currentVersion,
					Registry:       "nuget",
					Skipped:        true,
					SkipReason:     "package not found",
				})
				mu.Unlock()
				return
			}

			latestVersion := packageInfo.Data[0].Version

			// Apply version constraints if specified
			if constraint, ok := constraints[packageName]; ok && constraint.MajorVersion != nil {
				// Extract available versions from package info
				versions := packageInfo.Data[0].Versions
				if len(versions) == 0 {
					// Fallback to the current version if no versions array
					versions = []struct {
						Version string `json:"version"`
						ID      string `json:"@id"`
					}{{Version: packageInfo.Data[0].Version, ID: ""}}
				}

				// Filter versions by major version constraint
				var allowedVersions []string
				majorConstraint := *constraint.MajorVersion
				for _, versionInfo := range versions {
					version := versionInfo.Version
					if major, err := ExtractMajorVersion(version); err == nil && major == majorConstraint {
						allowedVersions = append(allowedVersions, version)
					}
				}

				if len(allowedVersions) > 0 {
					// Sort versions and get the latest one that matches constraints
					sort.Slice(allowedVersions, func(i, j int) bool {
						// Use version comparison for proper sorting
						if cmp, err := CompareVersions(allowedVersions[i], allowedVersions[j]); err == nil {
							return cmp < 0
						}
						// Fallback to string comparison if version parsing fails
						return allowedVersions[i] < allowedVersions[j]
					})
					latestVersion = allowedVersions[len(allowedVersions)-1]
				}
			}

			mu.Lock()
			result = append(result, PackageVersion{
				Name:           packageName,
				CurrentVersion: &currentVersion,
				LatestVersion:  latestVersion,
				Registry:       "nuget",
			})
			mu.Unlock()
		}(dep)
	}

	wg.Wait()

	// Sort results by name for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	// Create result
	resultData := map[string]interface{}{
		"packages": result,
	}

	// Use NewToolResultJSON to construct the result
	toolResult, err := NewToolResultJSON(resultData)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool result: %w", err)
	}
	return toolResult, nil
}
