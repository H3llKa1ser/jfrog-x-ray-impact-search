///////////////////////////////////////////////////////////////////////////////
//  check_cves_xray.go
//
//  Reads a CSV file of packages and checks each one for known CVEs
//  using the JFrog Xray REST API on your private on-premises instance.
//
//  It supports multiple ecosystems (npm, pypi, maven, nuget, go, docker,
//  gems, cargo, composer, helm, debian, rpm, alpine, cocoapods, conan).
//
//  BUILD:
//    go build -o check_cves_xray check_cves_xray.go
//
//  CROSS-COMPILE FOR WINDOWS:
//    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o check_cves_xray.exe check_cves_xray.go
//
//  USAGE:
//    ./check_cves_xray -csv packages.csv -host https://artifactory.mycompany.com -user admin -pass secret
//    ./check_cves_xray -csv packages.csv -host https://artifactory.mycompany.com -token your-access-token
//    ./check_cves_xray -csv packages.csv -host https://artifactory.mycompany.com -user admin -pass secret -severity Critical,High
//    ./check_cves_xray -csv packages.csv -output cve_report.csv -workers 20
//
//  REQUIREMENTS: Go 1.22.2+
///////////////////////////////////////////////////////////////////////////////

package main

import (
    "bytes"
    "crypto/tls"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "os"
    "runtime"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

// ========================== CONFIGURATION ====================================

const (
    defaultHost       = "https://artifactory.mycompany.com"
    defaultUsername    = ""
    defaultPassword   = ""
    defaultToken      = ""
    defaultOutputFile = "cve_report.csv"
    defaultMaxWorkers = 20
    defaultTimeout    = 30
    defaultSkipHeader = true
    defaultInsecure   = false
)

// =============================================================================

// ---- Terminal Colors ----
var (
    cRed    = "\033[0;31m"
    cGreen  = "\033[0;32m"
    cYellow = "\033[1;33m"
    cCyan   = "\033[0;36m"
    cBold   = "\033[1m"
    cReset  = "\033[0m"
)

// ---- Config ----
type Config struct {
    Host       string
    Username   string
    Password   string
    Token      string
    CSVFile    string
    OutputFile string
    MaxWorkers int
    Timeout    int
    SkipHeader bool
    Insecure   bool
    Severities []string // Filter: only report these severities
}

// ---- Package from CSV ----
type Package struct {
    Index     int
    Ecosystem string
    Namespace string
    Name      string
    Version   string
}

// ---- CVE Result ----
type CVEDetail struct {
    CVEID       string
    Severity    string
    Score       float64
    Description string
    FixedIn     string
    References  string
}

// ---- Package Result ----
type PackageResult struct {
    Package    Package
    Status     string // "VULNERABLE", "CLEAN", "NOT_FOUND", "ERROR"
    CVEs       []CVEDetail
    TotalCVEs  int
    ErrorMsg   string
}

///////////////////////////////////////////////////////////////////////////////
//  XRAY API REQUEST / RESPONSE STRUCTURES
///////////////////////////////////////////////////////////////////////////////

// ---- Xray Component Detail Request ----
// POST /xray/api/v1/component/details
type XrayComponentDetailRequest struct {
    ComponentDetails []XrayComponentID `json:"component_details"`
}

type XrayComponentID struct {
    ComponentID string `json:"component_id"`
}

// ---- Xray Summary/Artifact Request ----
// POST /xray/api/v2/summary/component
type XraySummaryRequest struct {
    ComponentDetails []XraySummaryComponent `json:"component_details"`
}

type XraySummaryComponent struct {
    ComponentID string `json:"component_id"`
}

// ---- Xray Summary Response ----
type XraySummaryResponse struct {
    Artifacts []XrayArtifact `json:"artifacts"`
    Errors    []XrayError    `json:"errors"`
}

type XrayArtifact struct {
    General  XrayGeneral  `json:"general"`
    Issues   []XrayIssue  `json:"issues"`
    Licenses []XrayLicense `json:"licenses"`
}

type XrayGeneral struct {
    Name        string `json:"name"`
    Path        string `json:"path"`
    PkgType     string `json:"pkg_type"`
    SHA256      string `json:"sha256"`
    ComponentID string `json:"component_id"`
}

type XrayIssue struct {
    Summary     string         `json:"summary"`
    Description string         `json:"description"`
    IssueType   string         `json:"issue_type"`
    Severity    string         `json:"severity"`
    Provider    string         `json:"provider"`
    Cves        []XrayCVE      `json:"cves"`
    Components  []XrayCompRef  `json:"components"`
    Created     string         `json:"created"`
}

type XrayCVE struct {
    CVE     string    `json:"cve"`
    CvssV2  string    `json:"cvss_v2"`
    CvssV3  string    `json:"cvss_v3"`
    CWE     []string  `json:"cwe"`
    CvssV3Score float64 `json:"cvss_v3_score"`
    CvssV2Score float64 `json:"cvss_v2_score"`
}

type XrayCompRef struct {
    ID              string   `json:"id"`
    FixedVersions   []string `json:"fixed_versions"`
    ImpactedVersions []string `json:"impacted_versions"`
}

type XrayLicense struct {
    Name       string   `json:"name"`
    FullName   string   `json:"full_name"`
    Components []string `json:"components"`
}

type XrayError struct {
    Identifier string `json:"identifier"`
    Error      string `json:"error"`
}

///////////////////////////////////////////////////////////////////////////////
//  MAIN
///////////////////////////////////////////////////////////////////////////////

func main() {
    // Disable colors on Windows if needed
    if runtime.GOOS == "windows" {
        cRed = ""
        cGreen = ""
        cYellow = ""
        cCyan = ""
        cBold = ""
        cReset = ""
    }

    // ---- Parse flags ----
    config := parseFlags()

    // ---- Validate ----
    if config.CSVFile == "" {
        fmt.Printf("%sERROR: No CSV file provided.%s\n", cRed, cReset)
        fmt.Println("Usage: ./check_cves_xray -csv /path/to/packages.csv")
        flag.PrintDefaults()
        os.Exit(1)
    }

    if _, err := os.Stat(config.CSVFile); os.IsNotExist(err) {
        fmt.Printf("%sERROR: File '%s' not found.%s\n", cRed, config.CSVFile, cReset)
        os.Exit(1)
    }

    // ---- Resolve auth from env vars if not provided ----
    resolveAuth(&config)

    if config.Token == "" && (config.Username == "" || config.Password == "") {
        fmt.Printf("%sERROR: No credentials provided. Use -user/-pass, -token, or set environment variables.%s\n", cRed, cReset)
        fmt.Println("  Environment variables: XRAY_HOST, XRAY_USER, XRAY_PASSWORD, XRAY_TOKEN")
        os.Exit(1)
    }

    // ---- Create HTTP client ----
    httpClient := createHTTPClient(config)

    // ---- Print banner ----
    printBanner(config)

    // ---- Step 1: Verify Xray connectivity ----
    fmt.Printf("%s[STEP 1] Verifying Xray connectivity...%s\n", cCyan, cReset)
    if err := verifyXrayConnection(httpClient, config); err != nil {
        fmt.Printf("  %sERROR: Cannot connect to Xray: %v%s\n", cRed, err, cReset)
        fmt.Println("  Make sure Xray is enabled and accessible at your Artifactory instance.")
        os.Exit(1)
    }
    fmt.Printf("  %s✅ Xray is reachable and authenticated%s\n\n", cGreen, cReset)

    // ---- Step 2: Read CSV ----
    fmt.Printf("%s[STEP 2] Reading packages from CSV...%s\n", cCyan, cReset)
    packages, err := readCSV(config)
    if err != nil {
        fmt.Printf("  %sERROR: Failed to read CSV: %v%s\n", cRed, err, cReset)
        os.Exit(1)
    }

    if len(packages) == 0 {
        fmt.Printf("  %sERROR: No packages found in CSV.%s\n", cRed, cReset)
        os.Exit(1)
    }

    fmt.Printf("  %sTotal packages to scan: %d%s\n\n", cGreen, len(packages), cReset)

    // ---- Step 3: Scan packages for CVEs ----
    fmt.Printf("%s[STEP 3] Scanning packages for CVEs (workers: %d)...%s\n\n", cCyan, config.MaxWorkers, cReset)

    startTime := time.Now()
    results := scanAllPackages(httpClient, config, packages)
    elapsed := time.Since(startTime)

    // ---- Step 4: Write report ----
    fmt.Printf("\n%s[STEP 4] Writing report...%s\n", cCyan, cReset)
    if err := writeReport(config, results); err != nil {
        fmt.Printf("  %sERROR: Failed to write report: %v%s\n", cRed, err, cReset)
        os.Exit(1)
    }

    // ---- Step 5: Summary ----
    printSummary(config, results, elapsed)
}

///////////////////////////////////////////////////////////////////////////////
//  PARSE FLAGS
///////////////////////////////////////////////////////////////////////////////

func parseFlags() Config {
    config := Config{}
    var severities string

    flag.StringVar(&config.Host, "host", defaultHost, "Artifactory/Xray base URL")
    flag.StringVar(&config.Username, "user", defaultUsername, "Username for authentication")
    flag.StringVar(&config.Password, "pass", defaultPassword, "Password or API key")
    flag.StringVar(&config.Token, "token", defaultToken, "Access token (alternative to user/pass)")
    flag.StringVar(&config.CSVFile, "csv", "", "Path to input CSV file (required)")
    flag.StringVar(&config.OutputFile, "output", defaultOutputFile, "Path to output CSV report")
    flag.IntVar(&config.MaxWorkers, "workers", defaultMaxWorkers, "Max concurrent Xray requests")
    flag.IntVar(&config.Timeout, "timeout", defaultTimeout, "HTTP timeout in seconds")
    flag.BoolVar(&config.SkipHeader, "skip-header", defaultSkipHeader, "Skip first line of CSV (header)")
    flag.BoolVar(&config.Insecure, "insecure", defaultInsecure, "Skip TLS certificate verification")
    flag.StringVar(&severities, "severity", "", "Filter CVEs by severity (comma-separated: Critical,High,Medium,Low)")

    flag.Parse()

    if severities != "" {
        for _, s := range strings.Split(severities, ",") {
            config.Severities = append(config.Severities, strings.TrimSpace(s))
        }
    }

    return config
}

// ---- Resolve auth from environment variables ----
func resolveAuth(config *Config) {
    if config.Host == defaultHost || config.Host == "" {
        if env := os.Getenv("XRAY_HOST"); env != "" {
            config.Host = env
        } else if env := os.Getenv("ARTIFACTORY_HOST"); env != "" {
            config.Host = env
        }
    }
    if config.Token == "" {
        if env := os.Getenv("XRAY_TOKEN"); env != "" {
            config.Token = env
        } else if env := os.Getenv("ARTIFACTORY_TOKEN"); env != "" {
            config.Token = env
        }
    }
    if config.Username == "" {
        if env := os.Getenv("XRAY_USER"); env != "" {
            config.Username = env
        } else if env := os.Getenv("ARTIFACTORY_USER"); env != "" {
            config.Username = env
        }
    }
    if config.Password == "" {
        if env := os.Getenv("XRAY_PASSWORD"); env != "" {
            config.Password = env
        } else if env := os.Getenv("ARTIFACTORY_PASSWORD"); env != "" {
            config.Password = env
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//  HTTP CLIENT
///////////////////////////////////////////////////////////////////////////////

func createHTTPClient(config Config) *http.Client {
    transport := &http.Transport{
        MaxIdleConns:        config.MaxWorkers + 10,
        MaxIdleConnsPerHost: config.MaxWorkers + 10,
        IdleConnTimeout:     90 * time.Second,
        DisableKeepAlives:   false,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: config.Insecure,
        },
    }

    return &http.Client{
        Timeout:   time.Duration(config.Timeout) * time.Second,
        Transport: transport,
    }
}

// ---- Create authenticated request ----
func newRequest(config Config, method, url string, body io.Reader) (*http.Request, error) {
    req, err := http.NewRequest(method, url, body)
    if err != nil {
        return nil, err
    }

    if config.Token != "" {
        req.Header.Set("Authorization", "Bearer "+config.Token)
    } else if config.Username != "" {
        req.SetBasicAuth(config.Username, config.Password)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    return req, nil
}

///////////////////////////////////////////////////////////////////////////////
//  VERIFY XRAY CONNECTION
///////////////////////////////////////////////////////////////////////////////

func verifyXrayConnection(client *http.Client, config Config) error {
    url := config.Host + "/xray/api/v1/system/ping"

    req, err := newRequest(config, "GET", url, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("connection failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        return fmt.Errorf("authentication failed (401) — check your credentials")
    }
    if resp.StatusCode == http.StatusForbidden {
        return fmt.Errorf("access denied (403) — insufficient permissions")
    }
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
    }

    return nil
}

///////////////////////////////////////////////////////////////////////////////
//  READ CSV
///////////////////////////////////////////////////////////////////////////////

func readCSV(config Config) ([]Package, error) {
    file, err := os.Open(config.CSVFile)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    reader.FieldsPerRecord = -1
    reader.LazyQuotes = true
    reader.TrimLeadingSpace = true

    var packages []Package
    lineNum := 0
    index := 0

    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            lineNum++
            continue
        }

        lineNum++

        if config.SkipHeader && lineNum == 1 {
            continue
        }

        if len(record) < 4 {
            continue
        }

        ecosystem := strings.TrimSpace(record[0])
        namespace := strings.TrimSpace(record[1])
        name := strings.TrimSpace(record[2])
        version := strings.TrimSpace(record[3])

        if name == "" || version == "" {
            continue
        }

        index++
        packages = append(packages, Package{
            Index:     index,
            Ecosystem: ecosystem,
            Namespace: namespace,
            Name:      name,
            Version:   version,
        })
    }

    return packages, nil
}

///////////////////////////////////////////////////////////////////////////////
//  BUILD XRAY COMPONENT ID
///////////////////////////////////////////////////////////////////////////////

// Xray uses a specific component ID format for each ecosystem:
//   npm:    npm://<scope>/<name>:<version>  or  npm://<name>:<version>
//   pypi:   pypi://<name>:<version>
//   maven:  gav://<groupId>:<artifactId>:<version>
//   nuget:  nuget://<name>:<version>
//   go:     go://<module>:<version>
//   docker: docker://<image>:<tag>
//   gems:   gem://<name>:<version>
//   cargo:  cargo://<name>:<version>
//   composer: composer://<vendor>/<name>:<version>
//   cocoapods: pod://<name>:<version>
//   conan:  conan://<name>:<version>
//   debian: deb://<name>:<version>
//   rpm:    rpm://<name>:<version>
//   alpine: alpine://<name>:<version>
//   helm:   helm://<name>:<version>

func buildComponentID(pkg Package) string {
    switch strings.ToLower(pkg.Ecosystem) {

    case "npm":
        if pkg.Namespace != "" {
            return fmt.Sprintf("npm://%s/%s:%s", pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("npm://%s:%s", pkg.Name, pkg.Version)

    case "pypi":
        return fmt.Sprintf("pypi://%s:%s", pkg.Name, pkg.Version)

    case "maven":
        if pkg.Namespace != "" {
            return fmt.Sprintf("gav://%s:%s:%s", pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("gav://%s:%s", pkg.Name, pkg.Version)

    case "nuget":
        return fmt.Sprintf("nuget://%s:%s", pkg.Name, pkg.Version)

    case "go", "golang":
        if pkg.Namespace != "" {
            return fmt.Sprintf("go://%s/%s:%s", pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("go://%s:%s", pkg.Name, pkg.Version)

    case "docker":
        if pkg.Namespace != "" {
            return fmt.Sprintf("docker://%s/%s:%s", pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("docker://%s:%s", pkg.Name, pkg.Version)

    case "gems", "rubygems", "gem":
        return fmt.Sprintf("gem://%s:%s", pkg.Name, pkg.Version)

    case "cargo", "crates":
        return fmt.Sprintf("cargo://%s:%s", pkg.Name, pkg.Version)

    case "composer", "php":
        if pkg.Namespace != "" {
            return fmt.Sprintf("composer://%s/%s:%s", pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("composer://%s:%s", pkg.Name, pkg.Version)

    case "cocoapods", "pods":
        return fmt.Sprintf("pod://%s:%s", pkg.Name, pkg.Version)

    case "conan":
        return fmt.Sprintf("conan://%s:%s", pkg.Name, pkg.Version)

    case "debian", "deb":
        return fmt.Sprintf("deb://%s:%s", pkg.Name, pkg.Version)

    case "rpm", "yum":
        return fmt.Sprintf("rpm://%s:%s", pkg.Name, pkg.Version)

    case "alpine", "apk":
        return fmt.Sprintf("alpine://%s:%s", pkg.Name, pkg.Version)

    case "helm":
        return fmt.Sprintf("helm://%s:%s", pkg.Name, pkg.Version)

    default:
        // Generic fallback
        if pkg.Namespace != "" {
            return fmt.Sprintf("%s://%s/%s:%s", pkg.Ecosystem, pkg.Namespace, pkg.Name, pkg.Version)
        }
        return fmt.Sprintf("%s://%s:%s", pkg.Ecosystem, pkg.Name, pkg.Version)
    }
}

///////////////////////////////////////////////////////////////////////////////
//  SCAN A SINGLE PACKAGE VIA XRAY API
///////////////////////////////////////////////////////////////////////////////

func scanPackage(client *http.Client, config Config, pkg Package) PackageResult {
    componentID := buildComponentID(pkg)

    // ---- Build request body ----
    reqBody := XraySummaryRequest{
        ComponentDetails: []XraySummaryComponent{
            {ComponentID: componentID},
        },
    }

    jsonBody, err := json.Marshal(reqBody)
    if err != nil {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("failed to marshal request: %v", err),
        }
    }

    // ---- POST to Xray Summary API ----
    url := config.Host + "/xray/api/v2/summary/component"

    req, err := newRequest(config, "POST", url, bytes.NewReader(jsonBody))
    if err != nil {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("failed to create request: %v", err),
        }
    }

    resp, err := client.Do(req)
    if err != nil {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("request failed: %v", err),
        }
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("failed to read response: %v", err),
        }
    }

    // ---- Handle HTTP errors ----
    if resp.StatusCode == http.StatusUnauthorized {
        return PackageResult{Package: pkg, Status: "ERROR", ErrorMsg: "authentication failed (401)"}
    }
    if resp.StatusCode == http.StatusForbidden {
        return PackageResult{Package: pkg, Status: "ERROR", ErrorMsg: "access denied (403)"}
    }
    if resp.StatusCode == http.StatusNotFound {
        return PackageResult{Package: pkg, Status: "NOT_FOUND", ErrorMsg: "component not found in Xray"}
    }
    if resp.StatusCode != http.StatusOK {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200)),
        }
    }

    // ---- Parse response ----
    var xrayResp XraySummaryResponse
    if err := json.Unmarshal(body, &xrayResp); err != nil {
        return PackageResult{
            Package:  pkg,
            Status:   "ERROR",
            ErrorMsg: fmt.Sprintf("failed to parse response: %v", err),
        }
    }

    // ---- Check for Xray-level errors ----
    if len(xrayResp.Errors) > 0 {
        errMsgs := make([]string, 0)
        for _, e := range xrayResp.Errors {
            errMsgs = append(errMsgs, e.Error)
        }
        return PackageResult{
            Package:  pkg,
            Status:   "NOT_FOUND",
            ErrorMsg: strings.Join(errMsgs, "; "),
        }
    }

    // ---- Extract CVEs ----
    var cves []CVEDetail

    for _, artifact := range xrayResp.Artifacts {
        for _, issue := range artifact.Issues {
            // Skip non-security issues
            if issue.IssueType != "security" && issue.IssueType != "" {
                continue
            }

            // ---- Severity filter ----
            if len(config.Severities) > 0 {
                matched := false
                for _, s := range config.Severities {
                    if strings.EqualFold(issue.Severity, s) {
                        matched = true
                        break
                    }
                }
                if !matched {
                    continue
                }
            }

            // ---- Extract CVE IDs and scores ----
            if len(issue.Cves) > 0 {
                for _, cve := range issue.Cves {
                    score := cve.CvssV3Score
                    if score == 0 {
                        score = cve.CvssV2Score
                    }

                    // ---- Get fixed versions ----
                    fixedVersions := ""
                    for _, comp := range issue.Components {
                        if len(comp.FixedVersions) > 0 {
                            fixedVersions = strings.Join(comp.FixedVersions, ", ")
                        }
                    }

                    cves = append(cves, CVEDetail{
                        CVEID:       cve.CVE,
                        Severity:    issue.Severity,
                        Score:       score,
                        Description: truncate(issue.Description, 300),
                        FixedIn:     fixedVersions,
                    })
                }
            } else {
                // Issue without specific CVE ID
                cves = append(cves, CVEDetail{
                    CVEID:       "N/A",
                    Severity:    issue.Severity,
                    Score:       0,
                    Description: truncate(issue.Description, 300),
                    FixedIn:     "",
                })
            }
        }
    }

    // ---- Sort CVEs by severity ----
    sort.Slice(cves, func(i, j int) bool {
        return severityRank(cves[i].Severity) > severityRank(cves[j].Severity)
    })

    // ---- Build result ----
    status := "CLEAN"
    if len(cves) > 0 {
        status = "VULNERABLE"
    }

    return PackageResult{
        Package:   pkg,
        Status:    status,
        CVEs:      cves,
        TotalCVEs: len(cves),
    }
}

///////////////////////////////////////////////////////////////////////////////
//  SCAN ALL PACKAGES IN PARALLEL
///////////////////////////////////////////////////////////////////////////////

func scanAllPackages(client *http.Client, config Config, packages []Package) []PackageResult {
    jobs := make(chan Package, config.MaxWorkers*2)
    resultsChan := make(chan PackageResult, len(packages))

    var completed atomic.Int32

    // ---- Start workers ----
    var wg sync.WaitGroup
    for i := 0; i < config.MaxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for pkg := range jobs {
                result := scanPackage(client, config, pkg)
                resultsChan <- result
                done := completed.Add(1)
                printProgress(result, int(done), len(packages))
            }
        }()
    }

    // ---- Feed jobs ----
    go func() {
        for _, pkg := range packages {
            jobs <- pkg
        }
        close(jobs)
    }()

    // ---- Wait and collect ----
    wg.Wait()
    close(resultsChan)

    // ---- Collect results and sort by index ----
    resultMap := make(map[int]PackageResult)
    for r := range resultsChan {
        resultMap[r.Package.Index] = r
    }

    results := make([]PackageResult, 0, len(packages))
    for _, pkg := range packages {
        if r, ok := resultMap[pkg.Index]; ok {
            results = append(results, r)
        }
    }

    return results
}

///////////////////////////////////////////////////////////////////////////////
//  PRINT PROGRESS
///////////////////////////////////////////////////////////////////////////////

func printProgress(result PackageResult, done, total int) {
    fullName := result.Package.Name
    if result.Package.Namespace != "" {
        fullName = result.Package.Namespace + "/" + result.Package.Name
    }

    prefix := fmt.Sprintf("  [%d/%d] %s%s@%s%s", done, total, cBold, fullName, result.Package.Version, cReset)

    switch result.Status {
    case "VULNERABLE":
        // Count by severity
        sevCounts := make(map[string]int)
        for _, cve := range result.CVEs {
            sevCounts[cve.Severity]++
        }
        sevSummary := formatSeverityCounts(sevCounts)
        fmt.Printf("%s ... %s🔴 %d CVE(s) [%s]%s\n", prefix, cRed, result.TotalCVEs, sevSummary, cReset)
    case "CLEAN":
        fmt.Printf("%s ... %s✅ No CVEs found%s\n", prefix, cGreen, cReset)
    case "NOT_FOUND":
        fmt.Printf("%s ... %s⚠️  Not found in Xray%s\n", prefix, cYellow, cReset)
    case "ERROR":
        fmt.Printf("%s ... %s❌ Error: %s%s\n", prefix, cRed, result.ErrorMsg, cReset)
    }
}

///////////////////////////////////////////////////////////////////////////////
//  WRITE CSV REPORT
///////////////////////////////////////////////////////////////////////////////

func writeReport(config Config, results []PackageResult) error {
    file, err := os.Create(config.OutputFile)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // ---- Header ----
    header := []string{
        "Ecosystem", "Namespace", "Name", "Version",
        "Status", "Total_CVEs",
        "CVE_ID", "Severity", "CVSS_Score",
        "Fixed_In", "Description",
    }
    if err := writer.Write(header); err != nil {
        return err
    }

    // ---- Data rows ----
    for _, r := range results {
        if len(r.CVEs) == 0 {
            // Write one row even if no CVEs
            row := []string{
                r.Package.Ecosystem,
                r.Package.Namespace,
                r.Package.Name,
                r.Package.Version,
                r.Status,
                fmt.Sprintf("%d", r.TotalCVEs),
                "", "", "", "", "",
            }
            if r.ErrorMsg != "" {
                row[10] = r.ErrorMsg
            }
            if err := writer.Write(row); err != nil {
                return err
            }
        } else {
            // One row per CVE
            for _, cve := range r.CVEs {
                row := []string{
                    r.Package.Ecosystem,
                    r.Package.Namespace,
                    r.Package.Name,
                    r.Package.Version,
                    r.Status,
                    fmt.Sprintf("%d", r.TotalCVEs),
                    cve.CVEID,
                    cve.Severity,
                    fmt.Sprintf("%.1f", cve.Score),
                    cve.FixedIn,
                    cve.Description,
                }
                if err := writer.Write(row); err != nil {
                    return err
                }
            }
        }
    }

    return nil
}

///////////////////////////////////////////////////////////////////////////////
//  PRINT SUMMARY
///////////////////////////////////////////////////////////////////////////////

func printSummary(config Config, results []PackageResult, elapsed time.Duration) {
    var (
        totalPkgs      = len(results)
        vulnerable     = 0
        clean          = 0
        notFound       = 0
        errors         = 0
        totalCVEs      = 0
        severityCounts = make(map[string]int)
    )

    for _, r := range results {
        switch r.Status {
        case "VULNERABLE":
            vulnerable++
            totalCVEs += r.TotalCVEs
            for _, cve := range r.CVEs {
                severityCounts[cve.Severity]++
            }
        case "CLEAN":
            clean++
        case "NOT_FOUND":
            notFound++
        case "ERROR":
            errors++
        }
    }

    fmt.Println()
    fmt.Println("============================================================")
    fmt.Println("  CVE SCAN SUMMARY")
    fmt.Println("============================================================")
    fmt.Printf("  Total Packages Scanned : %s%d%s\n", cCyan, totalPkgs, cReset)
    fmt.Printf("  🔴 Vulnerable          : %s%d%s\n", cRed, vulnerable, cReset)
    fmt.Printf("  ✅ Clean               : %s%d%s\n", cGreen, clean, cReset)
    fmt.Printf("  ⚠️  Not Found in Xray   : %s%d%s\n", cYellow, notFound, cReset)
    fmt.Printf("  ❌ Errors              : %s%d%s\n", cRed, errors, cReset)
    fmt.Println("------------------------------------------------------------")
    fmt.Printf("  Total CVEs Found       : %s%d%s\n", cRed, totalCVEs, cReset)

    if totalCVEs > 0 {
        fmt.Println()
        fmt.Println("  CVEs by Severity:")
        for _, sev := range []string{"Critical", "High", "Medium", "Low", "Information", "Unknown"} {
            if count, ok := severityCounts[sev]; ok {
                color := severityColor(sev)
                fmt.Printf("    %s%-12s : %d%s\n", color, sev, count, cReset)
            }
        }
        // Catch any other severities
        for sev, count := range severityCounts {
            found := false
            for _, known := range []string{"Critical", "High", "Medium", "Low", "Information", "Unknown"} {
                if sev == known {
                    found = true
                    break
                }
            }
            if !found {
                fmt.Printf("    %-12s : %d\n", sev, count)
            }
        }
    }

    // ---- Top vulnerable packages ----
    if vulnerable > 0 {
        fmt.Println()
        fmt.Println("  Top Vulnerable Packages:")

        // Sort by CVE count descending
        vulnResults := make([]PackageResult, 0)
        for _, r := range results {
            if r.Status == "VULNERABLE" {
                vulnResults = append(vulnResults, r)
            }
        }
        sort.Slice(vulnResults, func(i, j int) bool {
            return vulnResults[i].TotalCVEs > vulnResults[j].TotalCVEs
        })

        limit := 10
        if len(vulnResults) < limit {
            limit = len(vulnResults)
        }
        for i := 0; i < limit; i++ {
            r := vulnResults[i]
            fullName := r.Package.Name
            if r.Package.Namespace != "" {
                fullName = r.Package.Namespace + "/" + r.Package.Name
            }
            sevCounts := make(map[string]int)
            for _, cve := range r.CVEs {
                sevCounts[cve.Severity]++
            }
            fmt.Printf("    %s%-40s%s  %d CVEs  [%s]\n",
                cBold, fullName+"@"+r.Package.Version, cReset,
                r.TotalCVEs, formatSeverityCounts(sevCounts))
        }
    }

    fmt.Println()
    fmt.Println("------------------------------------------------------------")
    fmt.Printf("  Workers        : %s%d concurrent%s\n", cCyan, config.MaxWorkers, cReset)
    fmt.Printf("  Time Elapsed   : %s%s%s\n", cCyan, elapsed.Round(time.Millisecond), cReset)
    fmt.Printf("  Scan Rate      : %s%.1f packages/sec%s\n", cCyan, float64(totalPkgs)/elapsed.Seconds(), cReset)

    if len(config.Severities) > 0 {
        fmt.Printf("  Severity Filter: %s%s%s\n", cYellow, strings.Join(config.Severities, ", "), cReset)
    }

    fmt.Println("============================================================")
    fmt.Printf("  Report saved to: %s\n", config.OutputFile)
    fmt.Println("============================================================")
    fmt.Println()
}

///////////////////////////////////////////////////////////////////////////////
//  HELPERS
///////////////////////////////////////////////////////////////////////////////

func severityRank(severity string) int {
    switch strings.ToLower(severity) {
    case "critical":
        return 5
    case "high":
        return 4
    case "medium":
        return 3
    case "low":
        return 2
    case "information":
        return 1
    default:
        return 0
    }
}

func severityColor(severity string) string {
    switch strings.ToLower(severity) {
    case "critical":
        return cRed
    case "high":
        return cRed
    case "medium":
        return cYellow
    case "low":
        return cCyan
    default:
        return cReset
    }
}

func formatSeverityCounts(counts map[string]int) string {
    parts := make([]string, 0)
    for _, sev := range []string{"Critical", "High", "Medium", "Low", "Information"} {
        if count, ok := counts[sev]; ok {
            parts = append(parts, fmt.Sprintf("%s:%d", sev[:1], count))
        }
    }
    if len(parts) == 0 {
        return "Unknown"
    }
    return strings.Join(parts, " ")
}

func truncate(s string, maxLen int) string {
    s = strings.ReplaceAll(s, "\n", " ")
    s = strings.ReplaceAll(s, "\r", " ")
    s = strings.ReplaceAll(s, "\"", "'")
    if len(s) > maxLen {
        return s[:maxLen] + "..."
    }
    return s
}

///////////////////////////////////////////////////////////////////////////////
//  BANNER
///////////////////////////////////////////////////////////////////////////////

func printBanner(config Config) {
    fmt.Println()
    fmt.Println("============================================================")
    fmt.Println("  JFrog Xray — CVE Scanner for Packages")
    fmt.Println("============================================================")
    fmt.Printf("  Xray Host   : %s\n", config.Host)
    fmt.Printf("  CSV File    : %s\n", config.CSVFile)
    fmt.Printf("  Output File : %s\n", config.OutputFile)
    fmt.Printf("  Workers     : %d concurrent\n", config.MaxWorkers)
    fmt.Printf("  Timeout     : %ds\n", config.Timeout)
    fmt.Printf("  Insecure    : %v\n", config.Insecure)
    if len(config.Severities) > 0 {
        fmt.Printf("  Severity    : %s (filtered)\n", strings.Join(config.Severities, ", "))
    } else {
        fmt.Printf("  Severity    : All\n")
    }
    fmt.Println("============================================================")
    fmt.Println()
}
