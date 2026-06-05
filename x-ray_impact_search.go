///////////////////////////////////////////////////////////////////////////////
//  xray_impact_search.go
//
//  JFrog Xray Impact Search — complete implementation supporting ALL modes:
//
//  API: GET /xray/api/v2/search/impactedResources
//  Auth: Basic auth (username:password)
//
//  Search Modes (from Xray error message):
//    1. ?vulnerability=CVE-XXXX-XXXXX           — Search by CVE/XRAY ID
//    2. ?type=npm&name=abbrev&version=1.1.1     — Search by package
//    3. ?type=npm&name=abbrev                   — Search by package (any version)
//    4. ?service_name=my-service                — Search by service name
//
//  Response: {"result":[...], "last_key":"..."} with pagination
//  Error:    {"error":"..."} (CVE not found, mandatory params, etc.)
//
//  INPUT CSV FORMATS:
//    Mode: vulnerability
//      CVE-2024-29041
//      XRAY-989492
//
//    Mode: package (same as your existing package CSV)
//      Ecosystem,Namespace,Name,Version,Published,Detected
//      npm,,abbrev,1.1.1,,
//      npm,@uipath,cli,1.0.1,,
//
//  BUILD:
//    go build -o xray_impact_search xray_impact_search.go
//
//  WINDOWS:
//    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o xray_impact_search.exe xray_impact_search.go
//
//  USAGE:
//    # Search by CVE/XRAY IDs
//    ./xray_impact_search -csv cves.csv -mode vulnerability -host https://jfrog.company.tech -user admin -pass secret
//
//    # Search by packages
//    ./xray_impact_search -csv packages.csv -mode package -host https://jfrog.company.tech -user admin -pass secret
//
//    # Dry run / debug
//    ./xray_impact_search -csv packages.csv -mode package -dry-run
//    ./xray_impact_search -csv cves.csv -mode vulnerability -debug
//
//  REQUIREMENTS: Go 1.22.2+
///////////////////////////////////////////////////////////////////////////////

package main

import (
    "crypto/tls"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "runtime"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

const (
    defaultHost       = "https://jfrog.company.tech"
    defaultOutputFile = "xray_impact_report.csv"
    defaultMaxWorkers = 10
    defaultTimeout    = 60
    defaultLimit      = 100
    defaultMaxPages   = 50
    defaultInsecure   = false
    defaultMode       = "auto"
)

var (
    cRed    = "\033[0;31m"
    cGreen  = "\033[0;32m"
    cYellow = "\033[1;33m"
    cCyan   = "\033[0;36m"
    cBold   = "\033[1m"
    cReset  = "\033[0m"
    cGray   = "\033[0;37m"
)

///////////////////////////////////////////////////////////////////////////////
//  CONFIG
///////////////////////////////////////////////////////////////////////////////

type Config struct {
    Host       string
    Username   string
    Password   string
    Token      string
    CSVFile    string
    OutputFile string
    MaxWorkers int
    Timeout    int
    Limit      int
    MaxPages   int
    Insecure   bool
    Debug      bool
    DryRun     bool
    Mode       string // "vulnerability", "package", "auto"
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH QUERY — UNIFIED FOR ALL MODES
///////////////////////////////////////////////////////////////////////////////

type SearchQuery struct {
    Index int
    Mode  string // "vulnerability" or "package"

    // For vulnerability mode
    VulnerabilityID string

    // For package mode
    PackageType    string
    PackageName    string
    PackageVersion string

    // Display
    DisplayName string
}

func (q SearchQuery) BuildURL(host string, limit int, lastKey string) string {
    base := strings.TrimRight(host, "/") +
        "/xray/api/v2/search/impactedResources"

    params := url.Values{}
    params.Set("limit", fmt.Sprintf("%d", limit))

    switch q.Mode {
    case "vulnerability":
        params.Set("vulnerability", q.VulnerabilityID)
    case "package":
        params.Set("type", q.PackageType)
        params.Set("name", q.PackageName)
        if q.PackageVersion != "" {
            params.Set("version", q.PackageVersion)
        }
    }

    if lastKey != "" {
        params.Set("last_key", lastKey)
    }

    return base + "?" + params.Encode()
}

func (q SearchQuery) DedupeKey() string {
    switch q.Mode {
    case "vulnerability":
        return "vuln|" + strings.ToUpper(q.VulnerabilityID)
    case "package":
        return "pkg|" + strings.ToLower(q.PackageType) + "|" +
            strings.ToLower(q.PackageName) + "|" + q.PackageVersion
    }
    return ""
}

///////////////////////////////////////////////////////////////////////////////
//  XRAY RESPONSE
///////////////////////////////////////////////////////////////////////////////

type XrayResponse struct {
    Result  []ImpactedResource `json:"result"`
    LastKey string             `json:"last_key"`
}

type XrayErrorResponse struct {
    Error string `json:"error"`
}

type ImpactedResource struct {
    Type               string     `json:"type"`
    Name               string     `json:"name"`
    Path               string     `json:"path"`
    Repo               string     `json:"repo"`
    ArtifactName       string     `json:"artifact_name"`
    ArtifactPkgVersion PkgVersion `json:"artifact_pkg_version"`
    ScanDate           string     `json:"scan_date"`
    ImpactedPkgVersion PkgVersion `json:"impacted_pkg_version"`
}

type PkgVersion struct {
    Type      string `json:"type"`
    Name      string `json:"name"`
    Namespace string `json:"namespace"`
    Version   string `json:"version"`
    Ecosystem string `json:"ecosystem"`
}

func (r ImpactedResource) ArtifactDisplayName() string {
    name := strings.TrimSuffix(r.ArtifactPkgVersion.Name, ":sha256")
    ver := r.ArtifactPkgVersion.Version
    if len(ver) == 64 && !strings.Contains(ver, ".") {
        ver = ver[:12] + "..."
    }
    return fmt.Sprintf("%s:%s", name, ver)
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH RESULT
///////////////////////////////////////////////////////////////////////////////

type SearchResult struct {
    Query          SearchQuery
    Status         string // "FOUND", "NOT_FOUND", "ERROR"
    Resources      []ImpactedResource
    TotalResources int
    Pages          int
    ErrorMsg       string
}

///////////////////////////////////////////////////////////////////////////////
//  MAIN
///////////////////////////////////////////////////////////////////////////////

func main() {
    if runtime.GOOS == "windows" {
        cRed, cGreen, cYellow, cCyan, cBold, cReset, cGray = "", "", "", "", "", "", ""
    }

    config := parseFlags()

    if config.CSVFile == "" {
        printUsage()
        os.Exit(1)
    }

    if _, err := os.Stat(config.CSVFile); os.IsNotExist(err) {
        fmt.Printf("%sERROR: File '%s' not found.%s\n", cRed, config.CSVFile, cReset)
        os.Exit(1)
    }

    resolveAuth(&config)

    if !config.DryRun && config.Token == "" && (config.Username == "" || config.Password == "") {
        fmt.Printf("%sERROR: No credentials.%s\n", cRed, cReset)
        os.Exit(1)
    }

    httpClient := createHTTPClient(config)
    printBanner(config)

    // Step 1: Verify
    if !config.DryRun {
        fmt.Printf("%s[STEP 1] Verifying Xray connectivity...%s\n", cCyan, cReset)
        if err := verifyConnection(httpClient, config); err != nil {
            fmt.Printf("  %sERROR: %v%s\n", cRed, err, cReset)
            os.Exit(1)
        }
        fmt.Printf("  %s✅ Connected%s\n\n", cGreen, cReset)
    }

    // Step 2: Read CSV and build queries
    fmt.Printf("%s[STEP 2] Reading CSV and building queries...%s\n", cCyan, cReset)
    queries, dupsRemoved, parseErrors, detectedMode, err := readCSV(config)
    if err != nil {
        fmt.Printf("  %sERROR: %v%s\n", cRed, err, cReset)
        os.Exit(1)
    }
    if len(queries) == 0 {
        fmt.Printf("  %sERROR: No valid entries found.%s\n", cRed, cReset)
        os.Exit(1)
    }

    // Count by mode
    vulnCount, pkgCount := 0, 0
    for _, q := range queries {
        if q.Mode == "vulnerability" {
            vulnCount++
        } else {
            pkgCount++
        }
    }

    fmt.Printf("  %sDetected mode   : %s%s\n", cCyan, detectedMode, cReset)
    fmt.Printf("  %sTotal queries   : %d%s\n", cGreen, len(queries), cReset)
    if vulnCount > 0 {
        fmt.Printf("  %sVulnerability   : %d%s\n", cCyan, vulnCount, cReset)
    }
    if pkgCount > 0 {
        fmt.Printf("  %sPackage         : %d%s\n", cCyan, pkgCount, cReset)
    }
    if dupsRemoved > 0 {
        fmt.Printf("  %sDuplicates skip : %d%s\n", cYellow, dupsRemoved, cReset)
    }
    if parseErrors > 0 {
        fmt.Printf("  %sParse errors    : %d%s\n", cRed, parseErrors, cReset)
    }
    fmt.Println()

    // Dry run
    if config.DryRun {
        fmt.Printf("%s[DRY RUN] Requests that would be made:%s\n\n", cCyan, cReset)
        for _, q := range queries {
            reqURL := q.BuildURL(config.Host, config.Limit, "")
            fmt.Printf("  [%d] %s%s%s (%s)\n", q.Index, cBold, q.DisplayName, cReset, q.Mode)
            fmt.Printf("       %sGET %s%s\n\n", cGray, reqURL, cReset)
        }
        fmt.Printf("  Total: %d. Remove -dry-run to execute.\n\n", len(queries))
        return
    }

    // Step 3: Search
    fmt.Printf("%s[STEP 3] Searching %d queries (workers: %d, limit: %d/page, max pages: %d)...%s\n\n",
        cCyan, len(queries), config.MaxWorkers, config.Limit, config.MaxPages, cReset)

    startTime := time.Now()
    results := searchAll(httpClient, config, queries)
    elapsed := time.Since(startTime)

    // Step 4: Write
    fmt.Printf("\n%s[STEP 4] Writing report...%s\n", cCyan, cReset)
    if err := writeReport(config, results); err != nil {
        fmt.Printf("  %sERROR: %v%s\n", cRed, err, cReset)
        os.Exit(1)
    }

    printSummary(config, results, elapsed, dupsRemoved, parseErrors)
}

///////////////////////////////////////////////////////////////////////////////
//  FLAGS
///////////////////////////////////////////////////////////////////////////////

func parseFlags() Config {
    c := Config{}
    flag.StringVar(&c.Host, "host", defaultHost, "JFrog platform URL")
    flag.StringVar(&c.Username, "user", "", "Username")
    flag.StringVar(&c.Password, "pass", "", "Password or API key")
    flag.StringVar(&c.Token, "token", "", "Access token")
    flag.StringVar(&c.CSVFile, "csv", "", "Input CSV file (required)")
    flag.StringVar(&c.OutputFile, "output", defaultOutputFile, "Output report")
    flag.IntVar(&c.MaxWorkers, "workers", defaultMaxWorkers, "Concurrent requests")
    flag.IntVar(&c.Timeout, "timeout", defaultTimeout, "HTTP timeout (seconds)")
    flag.IntVar(&c.Limit, "limit", defaultLimit, "Results per page")
    flag.IntVar(&c.MaxPages, "max-pages", defaultMaxPages, "Max pages per query")
    flag.BoolVar(&c.Insecure, "insecure", defaultInsecure, "Skip TLS verification")
    flag.BoolVar(&c.Debug, "debug", false, "Show raw API traffic")
    flag.BoolVar(&c.DryRun, "dry-run", false, "Show URLs only")
    flag.StringVar(&c.Mode, "mode", defaultMode, "Search mode: vulnerability, package, or auto")
    flag.Parse()
    return c
}

func resolveAuth(c *Config) {
    envLookup := func(target *string, keys ...string) {
        if *target != "" {
            return
        }
        for _, k := range keys {
            if v := os.Getenv(k); v != "" {
                *target = v
                return
            }
        }
    }
    if c.Host == defaultHost {
        envLookup(&c.Host, "JFROG_HOST", "XRAY_HOST", "ARTIFACTORY_HOST")
    }
    envLookup(&c.Token, "JFROG_TOKEN", "XRAY_TOKEN", "ARTIFACTORY_TOKEN")
    envLookup(&c.Username, "JFROG_USER", "XRAY_USER", "ARTIFACTORY_USER")
    envLookup(&c.Password, "JFROG_PASSWORD", "XRAY_PASSWORD", "ARTIFACTORY_PASSWORD")
}

func printUsage() {
    fmt.Println("JFrog Xray Impact Search — All Modes")
    fmt.Println()
    fmt.Println("Usage:")
    fmt.Println("  # Search by CVE/XRAY IDs")
    fmt.Println("  ./xray_impact_search -csv cves.csv -mode vulnerability -host https://jfrog.company.tech -user admin -pass secret")
    fmt.Println()
    fmt.Println("  # Search by packages")
    fmt.Println("  ./xray_impact_search -csv packages.csv -mode package -host https://jfrog.company.tech -user admin -pass secret")
    fmt.Println()
    fmt.Println("  # Auto-detect mode")
    fmt.Println("  ./xray_impact_search -csv input.csv -host https://jfrog.company.tech -user admin -pass secret")
    fmt.Println()
    flag.PrintDefaults()
}

///////////////////////////////////////////////////////////////////////////////
//  HTTP
///////////////////////////////////////////////////////////////////////////////

func createHTTPClient(c Config) *http.Client {
    return &http.Client{
        Timeout: time.Duration(c.Timeout) * time.Second,
        Transport: &http.Transport{
            MaxIdleConns:        c.MaxWorkers + 10,
            MaxIdleConnsPerHost: c.MaxWorkers + 10,
            IdleConnTimeout:     90 * time.Second,
            TLSClientConfig:    &tls.Config{InsecureSkipVerify: c.Insecure},
        },
    }
}

func newRequest(c Config, reqURL string) (*http.Request, error) {
    req, err := http.NewRequest("GET", reqURL, nil)
    if err != nil {
        return nil, err
    }
    if c.Token != "" {
        req.Header.Set("Authorization", "Bearer "+c.Token)
    } else {
        req.SetBasicAuth(c.Username, c.Password)
    }
    req.Header.Set("Accept", "application/json")
    return req, nil
}

///////////////////////////////////////////////////////////////////////////////
//  VERIFY
///////////////////////////////////////////////////////////////////////////////

func verifyConnection(client *http.Client, c Config) error {
    testURL := strings.TrimRight(c.Host, "/") +
        "/xray/api/v2/search/impactedResources?vulnerability=CVE-0000-00000&limit=1"
    req, err := newRequest(c, testURL)
    if err != nil {
        return err
    }
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("cannot connect: %v", err)
    }
    defer resp.Body.Close()

    // Read body to check for SBOM disabled error
    body, _ := io.ReadAll(resp.Body)

    switch resp.StatusCode {
    case http.StatusUnauthorized:
        return fmt.Errorf("authentication failed (401)")
    case http.StatusForbidden:
        if strings.Contains(string(body), "SBOM") {
            return fmt.Errorf("SBOM is disabled on this instance — Impact Search requires SBOM to be enabled")
        }
        return fmt.Errorf("access denied (403)")
    default:
        return nil
    }
}

///////////////////////////////////////////////////////////////////////////////
//  READ CSV — AUTO-DETECT MODE
//
//  Vulnerability mode if:
//    - First column starts with CVE- or XRAY-
//    - User set -mode vulnerability
//
//  Package mode if:
//    - First column is an ecosystem (npm, pypi, maven, etc.)
//    - CSV has 4+ columns (ecosystem, namespace, name, version)
//    - User set -mode package
///////////////////////////////////////////////////////////////////////////////

func readCSV(c Config) ([]SearchQuery, int, int, string, error) {
    file, err := os.Open(c.CSVFile)
    if err != nil {
        return nil, 0, 0, "", err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    reader.FieldsPerRecord = -1
    reader.LazyQuotes = true
    reader.TrimLeadingSpace = true

    var queries []SearchQuery
    seen := make(map[string]bool)
    lineNum, idx, dups, errs := 0, 0, 0, 0
    detectedMode := c.Mode

    for {
        rec, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            lineNum++
            errs++
            continue
        }
        lineNum++

        if len(rec) == 0 {
            continue
        }

        // ---- Skip header row ----
        if lineNum == 1 {
            first := strings.ToLower(strings.TrimSpace(rec[0]))
            if first == "cve" || first == "cve_id" || first == "vulnerability" ||
                first == "vuln_id" || first == "issue_id" ||
                first == "ecosystem" || first == "type" || first == "package_type" {
                continue
            }
        }

        first := strings.TrimSpace(rec[0])

        // ---- Determine mode ----
        var query SearchQuery

        if c.Mode == "vulnerability" || (c.Mode == "auto" && isVulnID(first)) {
            // Vulnerability mode
            vulnID := strings.ToUpper(first)
            if !isVulnID(vulnID) {
                // Try to find vuln ID in other columns
                found := false
                for _, field := range rec {
                    f := strings.TrimSpace(field)
                    if isVulnID(f) {
                        vulnID = strings.ToUpper(f)
                        found = true
                        break
                    }
                }
                if !found {
                    errs++
                    continue
                }
            }

            query = SearchQuery{
                Mode:            "vulnerability",
                VulnerabilityID: vulnID,
                DisplayName:     vulnID,
            }
            detectedMode = "vulnerability"

        } else if c.Mode == "package" || (c.Mode == "auto" && isEcosystem(first)) {
            // Package mode: Ecosystem,Namespace,Name,Version,...
            if len(rec) < 3 {
                errs++
                continue
            }

            ecosystem := strings.TrimSpace(rec[0])
            namespace := ""
            name := ""
            version := ""

            if len(rec) >= 4 {
                namespace = strings.TrimSpace(rec[1])
                name = strings.TrimSpace(rec[2])
                version = strings.TrimSpace(rec[3])
            } else {
                name = strings.TrimSpace(rec[1])
                if len(rec) >= 3 {
                    version = strings.TrimSpace(rec[2])
                }
            }

            if name == "" {
                errs++
                continue
            }

            pkgType := normalizeEcosystem(ecosystem)

            // Build full package name
            fullName := name
            if namespace != "" {
                ns := namespace
                if pkgType == "npm" && !strings.HasPrefix(ns, "@") {
                    ns = "@" + ns
                }
                fullName = ns + "/" + name
            }

            displayName := fullName
            if version != "" {
                displayName = fullName + "@" + version
            }

            query = SearchQuery{
                Mode:           "package",
                PackageType:    pkgType,
                PackageName:    fullName,
                PackageVersion: version,
                DisplayName:    displayName,
            }
            detectedMode = "package"

        } else {
            // Could not determine mode
            errs++
            continue
        }

        // Deduplicate
        key := query.DedupeKey()
        if seen[key] {
            dups++
            continue
        }
        seen[key] = true

        idx++
        query.Index = idx
        queries = append(queries, query)
    }

    return queries, dups, errs, detectedMode, nil
}

func isVulnID(s string) bool {
    s = strings.ToUpper(strings.TrimSpace(s))
    return strings.HasPrefix(s, "CVE-") || strings.HasPrefix(s, "XRAY-")
}

func isEcosystem(s string) bool {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "npm", "pypi", "pip", "python", "maven", "mvn", "gradle",
        "nuget", "dotnet", "go", "golang", "docker", "container",
        "gems", "rubygems", "gem", "cargo", "crates", "rust",
        "composer", "php", "cocoapods", "pods", "conan",
        "debian", "deb", "rpm", "yum", "alpine", "apk", "helm":
        return true
    }
    return false
}

func normalizeEcosystem(e string) string {
    switch strings.ToLower(e) {
    case "npm":
        return "npm"
    case "pypi", "pip", "python":
        return "pypi"
    case "maven", "mvn", "gradle":
        return "maven"
    case "nuget", "dotnet":
        return "nuget"
    case "go", "golang":
        return "go"
    case "docker", "container", "oci":
        return "docker"
    case "gems", "rubygems", "gem":
        return "gems"
    case "cargo", "crates", "rust":
        return "cargo"
    case "composer", "php", "packagist":
        return "composer"
    case "cocoapods", "pods":
        return "cocoapods"
    case "conan":
        return "conan"
    case "debian", "deb":
        return "debian"
    case "rpm", "yum":
        return "rpm"
    case "alpine", "apk":
        return "alpine"
    case "helm":
        return "helm"
    default:
        return strings.ToLower(e)
    }
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH SINGLE QUERY — WITH PAGINATION
///////////////////////////////////////////////////////////////////////////////

func searchQuery(client *http.Client, c Config, query SearchQuery) SearchResult {
    var allResources []ImpactedResource
    lastKey := ""
    page := 0

    for {
        page++
        if page > c.MaxPages {
            break
        }

        reqURL := query.BuildURL(c.Host, c.Limit, lastKey)

        if c.Debug {
            fmt.Printf("    %s[DEBUG] GET %s (page %d)%s\n", cGray, reqURL, page, cReset)
        }

        req, err := newRequest(c, reqURL)
        if err != nil {
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: err.Error()}
        }

        resp, err := client.Do(req)
        if err != nil {
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: err.Error()}
        }

        body, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: err.Error()}
        }

        if c.Debug {
            fmt.Printf("    %s[DEBUG] HTTP %d (%d bytes)%s\n", cGray, resp.StatusCode, len(body), cReset)
            preview := string(body)
            if len(preview) > 1500 {
                preview = preview[:1500] + "..."
            }
            fmt.Printf("    %s[DEBUG] %s%s\n", cGray, preview, cReset)
        }

        switch resp.StatusCode {
        case http.StatusUnauthorized:
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: "auth failed (401)"}
        case http.StatusForbidden:
            bodyStr := string(body)
            if strings.Contains(bodyStr, "SBOM") {
                return SearchResult{Query: query, Status: "ERROR", ErrorMsg: "SBOM is disabled"}
            }
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: "access denied (403)"}
        case http.StatusNotFound:
            return SearchResult{Query: query, Status: "NOT_FOUND"}
        }

        if resp.StatusCode != http.StatusOK {
            return SearchResult{
                Query:    query,
                Status:   "ERROR",
                ErrorMsg: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200)),
            }
        }

        // Check error response
        var errResp XrayErrorResponse
        if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
            errLower := strings.ToLower(errResp.Error)
            if strings.Contains(errLower, "not found") ||
                strings.Contains(errLower, "doesn't exist") ||
                strings.Contains(errLower, "does not exist") ||
                strings.Contains(errLower, "mandatory parameters") {
                if len(allResources) > 0 {
                    break
                }
                return SearchResult{Query: query, Status: "NOT_FOUND", ErrorMsg: truncate(errResp.Error, 200)}
            }
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: truncate(errResp.Error, 200)}
        }

        // Parse success response
        var xrayResp XrayResponse
        if err := json.Unmarshal(body, &xrayResp); err != nil {
            return SearchResult{Query: query, Status: "ERROR", ErrorMsg: fmt.Sprintf("JSON error: %v", err)}
        }

        if len(xrayResp.Result) == 0 {
            break
        }

        allResources = append(allResources, xrayResp.Result...)

        if c.Debug {
            fmt.Printf("    %s[DEBUG] Page %d: %d results, total: %d, has_more: %v%s\n",
                cGray, page, len(xrayResp.Result), len(allResources), xrayResp.LastKey != "", cReset)
        }

        if xrayResp.LastKey == "" {
            break
        }
        lastKey = xrayResp.LastKey
    }

    if len(allResources) == 0 {
        return SearchResult{Query: query, Status: "NOT_FOUND"}
    }

    return SearchResult{
        Query:          query,
        Status:         "FOUND",
        Resources:      allResources,
        TotalResources: len(allResources),
        Pages:          page,
    }
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH ALL IN PARALLEL
///////////////////////////////////////////////////////////////////////////////

func searchAll(client *http.Client, c Config, queries []SearchQuery) []SearchResult {
    jobs := make(chan SearchQuery, c.MaxWorkers*2)
    resChan := make(chan SearchResult, len(queries))

    var completed atomic.Int32
    var wg sync.WaitGroup

    for i := 0; i < c.MaxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for q := range jobs {
                result := searchQuery(client, c, q)
                resChan <- result
                done := completed.Add(1)
                printProgress(result, int(done), len(queries))
            }
        }()
    }

    go func() {
        for _, q := range queries {
            jobs <- q
        }
        close(jobs)
    }()

    wg.Wait()
    close(resChan)

    rMap := make(map[int]SearchResult)
    for r := range resChan {
        rMap[r.Query.Index] = r
    }

    results := make([]SearchResult, 0, len(queries))
    for _, q := range queries {
        if r, ok := rMap[q.Index]; ok {
            results = append(results, r)
        }
    }
    return results
}

///////////////////////////////////////////////////////////////////////////////
//  PRINT PROGRESS
///////////////////////////////////////////////////////////////////////////////

func printProgress(r SearchResult, done, total int) {
    prefix := fmt.Sprintf("  [%d/%d] %s%s%s",
        done, total, cBold, r.Query.DisplayName, cReset)

    switch r.Status {
    case "FOUND":
        repos := make(map[string]bool)
        for _, res := range r.Resources {
            repos[res.Repo] = true
        }
        pageStr := ""
        if r.Pages > 1 {
            pageStr = fmt.Sprintf(", %d pages", r.Pages)
        }
        fmt.Printf("%s ... %s🔴 %d resource(s) in %d repo(s)%s%s\n",
            prefix, cRed, r.TotalResources, len(repos), pageStr, cReset)
    case "NOT_FOUND":
        fmt.Printf("%s ... %s✅ No impacted resources%s\n", prefix, cGreen, cReset)
    case "ERROR":
        fmt.Printf("%s ... %s❌ %s%s\n", prefix, cRed, r.ErrorMsg, cReset)
    }
}

///////////////////////////////////////////////////////////////////////////////
//  WRITE REPORT
///////////////////////////////////////////////////////////////////////////////

func writeReport(c Config, results []SearchResult) error {
    file, err := os.Create(c.OutputFile)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    header := []string{
        "Search_Mode",
        "Search_Query",
        "Status",
        "Total_Impacted_Resources",
        "Scan_Date",
        "Repository",
        "Artifact_Path",
        "Artifact_Type",
        "Artifact_Name",
        "Artifact_Version",
        "Artifact_Namespace",
        "Artifact_Ecosystem",
        "Impacted_Pkg_Type",
        "Impacted_Pkg_Name",
        "Impacted_Pkg_Version",
        "Impacted_Pkg_Namespace",
        "Impacted_Pkg_Ecosystem",
    }
    if err := writer.Write(header); err != nil {
        return err
    }

    for _, r := range results {
        if len(r.Resources) > 0 {
            for _, res := range r.Resources {
                artName := strings.TrimSuffix(res.ArtifactPkgVersion.Name, ":sha256")
                row := []string{
                    r.Query.Mode,
                    r.Query.DisplayName,
                    r.Status,
                    fmt.Sprintf("%d", r.TotalResources),
                    res.ScanDate,
                    res.Repo,
                    res.Path,
                    res.ArtifactPkgVersion.Type,
                    artName,
                    res.ArtifactPkgVersion.Version,
                    res.ArtifactPkgVersion.Namespace,
                    res.ArtifactPkgVersion.Ecosystem,
                    res.ImpactedPkgVersion.Type,
                    res.ImpactedPkgVersion.Name,
                    res.ImpactedPkgVersion.Version,
                    res.ImpactedPkgVersion.Namespace,
                    res.ImpactedPkgVersion.Ecosystem,
                }
                if err := writer.Write(row); err != nil {
                    return err
                }
            }
        } else {
            row := []string{
                r.Query.Mode,
                r.Query.DisplayName,
                r.Status,
                "0",
                "", "", "", "", "", "", "", "",
                "", "", "", "", "",
            }
            if err := writer.Write(row); err != nil {
                return err
            }
        }
    }
    return nil
}

///////////////////////////////////////////////////////////////////////////////
//  SUMMARY
///////////////////////////////////////////////////////////////////////////////

func printSummary(c Config, results []SearchResult, elapsed time.Duration, dupsRemoved, parseErrors int) {
    var found, notFound, errCount, totalRes int

    allRepos := make(map[string]bool)
    allArtifacts := make(map[string]bool)
    allImpactedPkgs := make(map[string]bool)
    var topResults []SearchResult

    for _, r := range results {
        switch r.Status {
        case "FOUND":
            found++
            totalRes += r.TotalResources
            topResults = append(topResults, r)
            for _, res := range r.Resources {
                allRepos[res.Repo] = true
                allArtifacts[strings.TrimSuffix(res.ArtifactPkgVersion.Name, ":sha256")] = true
                allImpactedPkgs[res.ImpactedPkgVersion.Name+"@"+res.ImpactedPkgVersion.Version] = true
            }
        case "NOT_FOUND":
            notFound++
        case "ERROR":
            errCount++
        }
    }

    fmt.Println()
    fmt.Println("============================================================")
    fmt.Println("  IMPACT SEARCH RESULTS")
    fmt.Println("============================================================")
    fmt.Printf("  Queries Executed         : %s%d%s\n", cCyan, len(results), cReset)
    fmt.Printf("  🔴 With Impacted Resources: %s%d%s\n", cRed, found, cReset)
    fmt.Printf("  ✅ No Impact              : %s%d%s\n", cGreen, notFound, cReset)
    fmt.Printf("  ❌ Errors                 : %s%d%s\n", cRed, errCount, cReset)
    fmt.Println("------------------------------------------------------------")
    fmt.Printf("  Total Impacted Resources : %s%d%s\n", cRed, totalRes, cReset)
    fmt.Printf("  Unique Repositories      : %s%d%s\n", cCyan, len(allRepos), cReset)
    fmt.Printf("  Unique Artifacts         : %s%d%s\n", cCyan, len(allArtifacts), cReset)
    fmt.Printf("  Unique Impacted Packages : %s%d%s\n", cCyan, len(allImpactedPkgs), cReset)

    if len(allRepos) > 0 && len(allRepos) <= 30 {
        fmt.Println()
        fmt.Println("  Repositories:")
        repos := make([]string, 0, len(allRepos))
        for r := range allRepos {
            repos = append(repos, r)
        }
        sort.Strings(repos)
        for _, r := range repos {
            fmt.Printf("    - %s\n", r)
        }
    }

    if len(topResults) > 0 {
        fmt.Println()
        fmt.Println("  Top Queries by Impact:")
        sort.Slice(topResults, func(i, j int) bool {
            return topResults[i].TotalResources > topResults[j].TotalResources
        })
        limit := 15
        if len(topResults) < limit {
            limit = len(topResults)
        }
        for i := 0; i < limit; i++ {
            r := topResults[i]
            repos := make(map[string]bool)
            for _, res := range r.Resources {
                repos[res.Repo] = true
            }
            fmt.Printf("    %s%-35s%s [%s] %4d resource(s) in %d repo(s)\n",
                cBold, r.Query.DisplayName, cReset,
                r.Query.Mode, r.TotalResources, len(repos))
        }
    }

    fmt.Println()
    fmt.Println("------------------------------------------------------------")
    if dupsRemoved > 0 {
        fmt.Printf("  Dupes removed    : %d\n", dupsRemoved)
    }
    if parseErrors > 0 {
        fmt.Printf("  Parse errors     : %d\n", parseErrors)
    }
    fmt.Printf("  Workers          : %d\n", c.MaxWorkers)
    fmt.Printf("  Limit/page       : %d\n", c.Limit)
    fmt.Printf("  Max pages/query  : %d\n", c.MaxPages)
    fmt.Printf("  Time             : %s\n", elapsed.Round(time.Millisecond))
    if elapsed.Seconds() > 0 {
        fmt.Printf("  Rate             : %.1f queries/sec\n", float64(len(results))/elapsed.Seconds())
    }
    fmt.Println("============================================================")
    fmt.Printf("  API: GET /xray/api/v2/search/impactedResources\n")
    fmt.Printf("  Modes: ?vulnerability=ID | ?type=T&name=N[&version=V]\n")
    fmt.Println("============================================================")
    fmt.Printf("  Report: %s\n", c.OutputFile)
    fmt.Println("============================================================")
    fmt.Println()
}

///////////////////////////////////////////////////////////////////////////////
//  HELPERS
///////////////////////////////////////////////////////////////////////////////

func truncate(s string, maxLen int) string {
    s = strings.ReplaceAll(s, "\n", " ")
    s = strings.ReplaceAll(s, "\r", " ")
    if len(s) > maxLen {
        return s[:maxLen] + "..."
    }
    return s
}

func printBanner(c Config) {
    fmt.Println()
    fmt.Println("============================================================")
    fmt.Println("  JFrog Xray — Impact Search (All Modes)")
    fmt.Println("============================================================")
    fmt.Printf("  Host           : %s\n", c.Host)
    fmt.Printf("  CSV            : %s\n", c.CSVFile)
    fmt.Printf("  Output         : %s\n", c.OutputFile)
    fmt.Printf("  Mode           : %s\n", c.Mode)
    fmt.Printf("  Workers        : %d\n", c.MaxWorkers)
    fmt.Printf("  Limit/page     : %d\n", c.Limit)
    fmt.Printf("  Max pages      : %d\n", c.MaxPages)
    fmt.Printf("  Timeout        : %ds\n", c.Timeout)
    fmt.Printf("  Debug          : %v\n", c.Debug)
    fmt.Printf("  Dry Run        : %v\n", c.DryRun)
    fmt.Println("============================================================")
    fmt.Println("  Supported search modes:")
    fmt.Println("    1. vulnerability : ?vulnerability=CVE-XXXX / XRAY-XXXXX")
    fmt.Println("    2. package       : ?type=npm&name=abbrev&version=1.1.1")
    fmt.Println("    3. auto          : auto-detect from CSV content")
    fmt.Println("============================================================")
    fmt.Println()
}
