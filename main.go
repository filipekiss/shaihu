package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type PackageInfo struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Dependencies    map[string]string      `json:"dependencies,omitempty"`
	DevDependencies map[string]string      `json:"devDependencies,omitempty"`
	PeerDependencies map[string]string     `json:"peerDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
}

type CompromisedPackage struct {
	Name     string
	Versions []string
}

type Vulnerability struct {
	PackageName    string
	Version        string
	CompromisedVersions []string
	File           string
	DependencyType string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <compromised-packages-file> <search-directory>\n", os.Args[0])
		os.Exit(1)
	}

	compromisedFile := os.Args[1]
	searchDir := os.Args[2]

	compromisedPackages, err := readCompromisedPackages(compromisedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading compromised packages file: %v\n", err)
		os.Exit(1)
	}

	packageJsonFiles, err := findPackageJsonFiles(searchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding package.json files: %v\n", err)
		os.Exit(1)
	}

	var vulnerabilities []Vulnerability
	for _, file := range packageJsonFiles {
		fmt.Printf("Analyzing: %s\n", file)
		vulns, err := analyzePackageJson(file, compromisedPackages)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n", file, err)
			continue
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	if len(vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found!")
		return
	}

	fmt.Printf("Found %d vulnerabilities:\n\n", len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		fmt.Printf("⚠️  Package: %s\n", vuln.PackageName)
		fmt.Printf("   Version: %s\n", vuln.Version)
		fmt.Printf("   Compromised versions: %s\n", strings.Join(vuln.CompromisedVersions, ", "))
		fmt.Printf("   File: %s\n", vuln.File)
		fmt.Printf("   Dependency type: %s\n\n", vuln.DependencyType)
	}
}

func readCompromisedPackages(filename string) (map[string][]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	compromised := make(map[string][]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}

		packageName := strings.TrimSpace(parts[0])
		versionsStr := strings.TrimSpace(parts[1])
		
		versions := strings.Split(versionsStr, ",")
		var cleanVersions []string
		for _, version := range versions {
			cleanVersion := strings.TrimSpace(version)
			if cleanVersion != "" {
				cleanVersions = append(cleanVersions, cleanVersion)
			}
		}

		if len(cleanVersions) > 0 {
			compromised[packageName] = cleanVersions
		}
	}

	return compromised, nil
}

func findPackageJsonFiles(rootDir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}

		if !d.IsDir() && d.Name() == "package.json" {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

func analyzePackageJson(filePath string, compromisedPackages map[string][]string) ([]Vulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pkg PackageInfo
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var vulnerabilities []Vulnerability

	dependencyTypes := map[string]map[string]string{
		"dependencies":         pkg.Dependencies,
		"devDependencies":      pkg.DevDependencies,
		"peerDependencies":     pkg.PeerDependencies,
		"optionalDependencies": pkg.OptionalDependencies,
	}

	for depType, deps := range dependencyTypes {
		for packageName, version := range deps {
			if compromisedVersions, exists := compromisedPackages[packageName]; exists {
				for _, compromisedVersion := range compromisedVersions {
					if version == compromisedVersion {
						vulnerabilities = append(vulnerabilities, Vulnerability{
							PackageName:         packageName,
							Version:             version,
							CompromisedVersions: compromisedVersions,
							File:                filePath,
							DependencyType:      depType,
						})
						break
					}
				}
			}
		}
	}

	return vulnerabilities, nil
}
