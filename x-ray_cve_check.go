///////////////////////////////////////////////////////////////////////////////
//  xray_cve_scanner.go
//
//  Searches JFrog Xray for impacted resources by CVE ID using:
//    GET /xray/api/v2/search/impactedResources?vulnerability=CVE-XXX&limit=N
//
//  Auth: Basic auth (username:password) on /xray/api/
//
//  RESPONSE FORMAT:
//    Success: {"result":[{...}], "last_key":"..."}
//    Error:   {"error":"CVE not found: ..."}
//
//  Supports PAGINATION via last_key to retrieve ALL impacted resources.
//
//  INPUT CSV — one CVE per line (or any column containing CVE IDs):
//    CVE-2024-29041
//    CVE-2023-44487
//    CVE-2021-44228
//
//  BUILD:
//    go build -o xray_cve_scanner xray_cve_scanner.go
//
//  WINDOWS:
//    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o xray_cve_scanner.exe xray_cve_scanner.go
//
//  USAGE:
//    ./xray_cve_scanner -csv cves.csv -host https://jfrog.company.tech -user admin -pass secret
//    ./xray_cve_scanner -csv cves.csv -limit 200 -max-pages 10
//    ./xray_cve_scanner -csv cves.csv -debug
//    ./xray_cve_scanner -csv cves.csv -dry-run
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
    defaultOutputFile = "xray_cve_report.csv"
    defaultMaxWorkers = 10
    defaultTimeout    = 60
    defaultLimit      = 100
    defaultMaxPages   = 50
    defaultInsecure   = false
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
//  DATA STRUCTURES
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
    CVEColumn  int
}

type CVEEntry struct {
    Index int
    CVEID string
}

///////////////////////////////////////////////////////////////////////////////
//  XRAY RESPONSE — YOUR EXACT FORMAT
///////////////////////////////////////////////////////////////////////////////

// Success response
type XrayResponse struct {
    Result  []ImpactedResource `json:"result"`
    LastKey string             `json:"last_key"`
}

// Error response
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

// ArtifactDisplayName returns a clean display name for the artifact
func (r ImpactedResource) ArtifactDisplayName() string {
    name := r.ArtifactPkgVersion.Name
    ver := r.ArtifactPkgVersion.Version

    // For sha256 digests, show only first 12 chars
    if len(ver) == 64 && !strings.Contains(ver, ".") {
        ver = ver[:12] + "..."
    }
    // Clean up name:sha256 format
    name = strings.TrimSuffix(name, ":sha256")

    return fmt.Sprintf("%s:%s", name, ver)
}

///////////////////////////////////////////////////////////////////////////////
//  CVE RESULT
///////////////////////////////////////////////////////////////////////////////

type CVEResult struct {
    CVE            CVEEntry
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
        fmt.Printf("%sERROR: No CSV file provided.%s\n", cRed, cReset)
        fmt.Println("Usage: ./xray_cve_scanner -csv cves.csv -host https://jfrog.company.tech -user admin -pass secret")
        fmt.Println()
        fmt.Println("CSV format — one CVE per line:")
        fmt.Println("  CVE-2024-29041")
        fmt.Println("  CVE-2023-44487")
        fmt.Println("  CVE-2021-44228")
        fmt.Println()
        flag.PrintDefaults()
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
        fmt.Printf("  %s✅ Connected (basic auth)%s\n\n", cGreen, cReset)
    }

    // Step 2: Read CSV
    fmt.Printf("%s[STEP 2] Reading CVEs...%s\n", cCyan, cReset)
    cves, dupsRemoved, parseErrors, err := readCVEs(config)
    if err != nil {
        fmt.Printf("  %sERROR: %v%s\n", cRed, err, cReset)
        os.Exit(1)
    }
    if len(cves) == 0 {
        fmt.Printf("  %sERROR: No valid CVE IDs found.%s\n", cRed, cReset)
        os.Exit(1)
    }
    fmt.Printf("  %sUnique CVEs     : %d%s\n", cGreen, len(cves), cReset)
    if dupsRemoved > 0 {
        fmt.Printf("  %sDuplicates skip : %d%s\n", cYellow, dupsRemoved, cReset)
    }
    if parseErrors > 0 {
        fmt.Printf("  %sParse errors    : %d%s\n", cRed, parseErrors, cReset)
    }
    fmt.Println()

    // Dry run
    if config.DryRun {
        fmt.Printf("%s[DRY RUN] Requests:%s\n\n", cCyan, cReset)
        for _, cve := range cves {
            fmt.Printf("  [%d] %s%s%s\n", cve.Index, cBold, cve.CVEID, cReset)
            fmt.Printf("       %sGET /xray/api/v2/search/impactedResources?vulnerability=%s&limit=%d%s\n\n",
                cGray, cve.CVEID, config.Limit, cReset)
        }
        fmt.Printf("  Total: %d. Remove -dry-run to execute.\n\n", len(cves))
        return
    }

    // Step 3: Search
    fmt.Printf("%s[STEP 3] Searching %d CVEs (workers: %d, limit: %d/page, max pages: %d)...%s\n\n",
        cCyan, len(cves), config.MaxWorkers, config.Limit, config.MaxPages, cReset)

    startTime := time.Now()
    results := searchAll(httpClient, config, cves)
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
//  FLAGS & AUTH
///////////////////////////////////////////////////////////////////////////////

func parseFlags() Config {
    c := Config{}
    flag.StringVar(&c.Host, "host", defaultHost, "JFrog platform URL")
    flag.StringVar(&c.Username, "user", "", "Username")
    flag.StringVar(&c.Password, "pass", "", "Password or API key")
    flag.StringVar(&c.Token, "token", "", "Access token")
    flag.StringVar(&c.CSVFile, "csv", "", "CSV file with CVE IDs (required)")
    flag.StringVar(&c.OutputFile, "output", defaultOutputFile, "Output CSV report")
    flag.IntVar(&c.MaxWorkers, "workers", defaultMaxWorkers, "Concurrent requests")
    flag.IntVar(&c.Timeout, "timeout", defaultTimeout, "HTTP timeout (seconds)")
    flag.IntVar(&c.Limit, "limit", defaultLimit, "Results per page")
    flag.IntVar(&c.MaxPages, "max-pages", defaultMaxPages, "Max pages to fetch per CVE (pagination)")
    flag.BoolVar(&c.Insecure, "insecure", defaultInsecure, "Skip TLS verification")
    flag.BoolVar(&c.Debug, "debug", false, "Show raw API requests/responses")
    flag.BoolVar(&c.DryRun, "dry-run", false, "Show URLs only")
    flag.IntVar(&c.CVEColumn, "cve-column", -1, "CSV column with CVE IDs (0-based, auto if -1)")
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
    // Test with a dummy CVE — any non-401/403 response means auth works
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

    switch resp.StatusCode {
    case http.StatusUnauthorized:
        return fmt.Errorf("authentication failed (401)")
    case http.StatusForbidden:
        return fmt.Errorf("access denied (403)")
    default:
        // 200 with {"error":"CVE not found"} = auth works, CVE just doesn't exist
        return nil
    }
}

///////////////////////////////////////////////////////////////////////////////
//  READ CVEs FROM CSV
///////////////////////////////////////////////////////////////////////////////

func readCVEs(c Config) ([]CVEEntry, int, int, error) {
    file, err := os.Open(c.CSVFile)
    if err != nil {
        return nil, 0, 0, err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    reader.FieldsPerRecord = -1
    reader.LazyQuotes = true
    reader.TrimLeadingSpace = true

    var cves []CVEEntry
    seen := make(map[string]bool)
    lineNum, idx, dups, errs := 0, 0, 0, 0
    cveCol := c.CVEColumn

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

        // Auto-detect header
        if lineNum == 1 {
            for i, field := range rec {
                f := strings.ToLower(strings.TrimSpace(field))
                if f == "cve" || f == "cve_id" || f == "vulnerability" || f == "vuln_id" || f == "issue_id" {
                    if cveCol < 0 {
                        cveCol = i
                    }
                    // Skip header row
                    goto nextLine
                }
            }
        }

        {
            cveID := ""

            if cveCol >= 0 && cveCol < len(rec) {
                cveID = strings.TrimSpace(rec[cveCol])
            } else {
                // Auto-detect: find CVE-XXXX-XXXXX pattern in any column
                for _, field := range rec {
                    f := strings.TrimSpace(field)
                    if isCVEID(f) {
                        cveID = f
                        break
                    }
                }
                // Fallback: first column
                if cveID == "" && len(rec) > 0 {
                    cveID = strings.TrimSpace(rec[0])
                }
            }

            if cveID == "" {
                errs++
                goto nextLine
            }

            cveID = strings.ToUpper(strings.TrimSpace(cveID))

            if !strings.HasPrefix(cveID, "CVE-") && !strings.HasPrefix(cveID, "XRAY-") {
                errs++
                goto nextLine
            }

            if seen[cveID] {
                dups++
                goto nextLine
            }
            seen[cveID] = true

            idx++
            cves = append(cves, CVEEntry{Index: idx, CVEID: cveID})
        }

    nextLine:
    }

    return cves, dups, errs, nil
}

func isCVEID(s string) bool {
    s = strings.ToUpper(strings.TrimSpace(s))
    if strings.HasPrefix(s, "XRAY-") {
        return true // Accept all XRAY-XXXXXX IDs
    }
    if !strings.HasPrefix(s, "CVE-") {
        return false
    }
    parts := strings.Split(s, "-")
    return len(parts) >= 3 && len(parts[1]) == 4 && len(parts[2]) >= 4
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH SINGLE CVE — WITH PAGINATION
//
//  Your API returns:
//    {"result":[...], "last_key":"base64..."}
//
//  If last_key is present, there are more results. We fetch the next page:
//    GET ...?vulnerability=CVE-XXX&limit=N&last_key=base64...
///////////////////////////////////////////////////////////////////////////////

func searchCVE(client *http.Client, c Config, cve CVEEntry) CVEResult {
    var allResources []ImpactedResource
    lastKey := ""
    page := 0

    for {
        page++
        if page > c.MaxPages {
            if c.Debug {
                fmt.Printf("    %s[DEBUG] Max pages (%d) reached for %s%s\n",
                    cGray, c.MaxPages, cve.CVEID, cReset)
            }
            break
        }

        // Build URL
        base := strings.TrimRight(c.Host, "/") +
            "/xray/api/v2/search/impactedResources"
        params := url.Values{}
        params.Set("vulnerability", cve.CVEID)
        params.Set("limit", fmt.Sprintf("%d", c.Limit))
        if lastKey != "" {
            params.Set("last_key", lastKey)
        }
        reqURL := base + "?" + params.Encode()

        if c.Debug {
            fmt.Printf("    %s[DEBUG] GET %s (page %d)%s\n", cGray, reqURL, page, cReset)
        }

        req, err := newRequest(c, reqURL)
        if err != nil {
            return CVEResult{CVE: cve, Status: "ERROR", ErrorMsg: err.Error()}
        }

        resp, err := client.Do(req)
        if err != nil {
            return CVEResult{CVE: cve, Status: "ERROR", ErrorMsg: err.Error()}
        }

        body, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            return CVEResult{CVE: cve, Status: "ERROR", ErrorMsg: err.Error()}
        }

        if c.Debug {
            fmt.Printf("    %s[DEBUG] HTTP %d (%d bytes)%s\n",
                cGray, resp.StatusCode, len(body), cReset)
            preview := string(body)
            if len(preview) > 1500 {
                preview = preview[:1500] + "..."
            }
            fmt.Printf("    %s[DEBUG] %s%s\n", cGray, preview, cReset)
        }

        // HTTP errors
        switch resp.StatusCode {
        case http.StatusUnauthorized:
            return CVEResult{CVE: cve, Status: "ERROR", ErrorMsg: "auth failed (401)"}
        case http.StatusForbidden:
            return CVEResult{CVE: cve, Status: "ERROR", ErrorMsg: "access denied (403)"}
        case http.StatusNotFound:
            return CVEResult{CVE: cve, Status: "NOT_FOUND"}
        }

        if resp.StatusCode != http.StatusOK {
            return CVEResult{
                CVE:      cve,
                Status:   "ERROR",
                ErrorMsg: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200)),
            }
        }

        // ---- Check for error response: {"error":"CVE not found: ..."} ----
        var errResp XrayErrorResponse
        if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
            errLower := strings.ToLower(errResp.Error)
            if strings.Contains(errLower, "not found") ||
                strings.Contains(errLower, "doesn't exist") ||
                strings.Contains(errLower, "does not exist") {
                // CVE not indexed — not an error, just no data
                if len(allResources) > 0 {
                    // We already got some results from previous pages
                    break
                }
                return CVEResult{CVE: cve, Status: "NOT_FOUND"}
            }
            return CVEResult{
                CVE:      cve,
                Status:   "ERROR",
                ErrorMsg: truncate(errResp.Error, 200),
            }
        }

        // ---- Parse success response: {"result":[...], "last_key":"..."} ----
        var xrayResp XrayResponse
        if err := json.Unmarshal(body, &xrayResp); err != nil {
            return CVEResult{
                CVE:      cve,
                Status:   "ERROR",
                ErrorMsg: fmt.Sprintf("JSON parse error: %v", err),
            }
        }

        if len(xrayResp.Result) == 0 {
            break // No more results
        }

        allResources = append(allResources, xrayResp.Result...)

        if c.Debug {
            fmt.Printf("    %s[DEBUG] Page %d: %d results, total so far: %d, last_key: %s%s\n",
                cGray, page, len(xrayResp.Result), len(allResources),
                truncate(xrayResp.LastKey, 30), cReset)
        }

        // Check for more pages
        if xrayResp.LastKey == "" {
            break // No more pages
        }

        lastKey = xrayResp.LastKey
    }

    if len(allResources) == 0 {
        return CVEResult{CVE: cve, Status: "NOT_FOUND"}
    }

    return CVEResult{
        CVE:            cve,
        Status:         "FOUND",
        Resources:      allResources,
        TotalResources: len(allResources),
        Pages:          page,
    }
}

///////////////////////////////////////////////////////////////////////////////
//  SEARCH ALL IN PARALLEL
///////////////////////////////////////////////////////////////////////////////

func searchAll(client *http.Client, c Config, cves []CVEEntry) []CVEResult {
    jobs := make(chan CVEEntry, c.MaxWorkers*2)
    resChan := make(chan CVEResult, len(cves))

    var completed atomic.Int32
    var wg sync.WaitGroup

    for i := 0; i < c.MaxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for cve := range jobs {
                result := searchCVE(client, c, cve)
                resChan <- result
                done := completed.Add(1)
                printProgress(result, int(done), len(cves))
            }
        }()
    }

    go func() {
        for _, cve := range cves {
            jobs <- cve
        }
        close(jobs)
    }()

    wg.Wait()
    close(resChan)

    rMap := make(map[int]CVEResult)
    for r := range resChan {
        rMap[r.CVE.Index] = r
    }

    results := make([]CVEResult, 0, len(cves))
    for _, cve := range cves {
        if r, ok := rMap[cve.Index]; ok {
            results = append(results, r)
        }
    }
    return results
}

///////////////////////////////////////////////////////////////////////////////
//  PRINT PROGRESS
///////////////////////////////////////////////////////////////////////////////

func printProgress(r CVEResult, done, total int) {
    prefix := fmt.Sprintf("  [%d/%d] %s%s%s",
        done, total, cBold, r.CVE.CVEID, cReset)

    switch r.Status {
    case "FOUND":
        // Count unique repos and artifact types
        repos := make(map[string]bool)
        impactedPkgs := make(map[string]bool)
        for _, res := range r.Resources {
            repos[res.Repo] = true
            impactedPkgs[res.ImpactedPkgVersion.Name+"@"+res.ImpactedPkgVersion.Version] = true
        }
        pageStr := ""
        if r.Pages > 1 {
            pageStr = fmt.Sprintf(", %d pages", r.Pages)
        }
        fmt.Printf("%s ... %s🔴 %d resource(s) in %d repo(s), %d impacted pkg(s)%s%s\n",
            prefix, cRed, r.TotalResources, len(repos), len(impactedPkgs), pageStr, cReset)
    case "NOT_FOUND":
        fmt.Printf("%s ... %s✅ No impacted resources%s\n", prefix, cGreen, cReset)
    case "ERROR":
        fmt.Printf("%s ... %s❌ %s%s\n", prefix, cRed, r.ErrorMsg, cReset)
    }
}

///////////////////////////////////////////////////////////////////////////////
//  WRITE REPORT
///////////////////////////////////////////////////////////////////////////////

func writeReport(c Config, results []CVEResult) error {
    file, err := os.Create(c.OutputFile)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    header := []string{
        "CVE_ID",
        "Status",
        "Total_Impacted_Resources",
        // Artifact (container) info
        "Scan_Date",
        "Repository",
        "Artifact_Path",
        "Artifact_Type",
        "Artifact_Name",
        "Artifact_Version",
        "Artifact_Namespace",
        "Artifact_Ecosystem",
        // Impacted package (dependency inside the artifact)
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
                // Clean artifact version for readability
                artVersion := res.ArtifactPkgVersion.Version
                artName := strings.TrimSuffix(res.ArtifactPkgVersion.Name, ":sha256")

                row := []string{
                    r.CVE.CVEID,
                    r.Status,
                    fmt.Sprintf("%d", r.TotalResources),
                    res.ScanDate,
                    res.Repo,
                    res.Path,
                    res.ArtifactPkgVersion.Type,
                    artName,
                    artVersion,
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
                r.CVE.CVEID,
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

func printSummary(c Config, results []CVEResult, elapsed time.Duration, dupsRemoved, parseErrors int) {
    var (
        found    int
        notFound int
        errCount int
        totalRes int
    )

    allRepos := make(map[string]bool)
    allImpactedPkgs := make(map[string]bool)
    allArtifacts := make(map[string]bool)
    topCVEs := make([]CVEResult, 0)

    for _, r := range results {
        switch r.Status {
        case "FOUND":
            found++
            totalRes += r.TotalResources
            topCVEs = append(topCVEs, r)
            for _, res := range r.Resources {
                allRepos[res.Repo] = true
                allImpactedPkgs[res.ImpactedPkgVersion.Name+"@"+res.ImpactedPkgVersion.Version] = true
                artName := strings.TrimSuffix(res.ArtifactPkgVersion.Name, ":sha256")
                allArtifacts[artName] = true
            }
        case "NOT_FOUND":
            notFound++
        case "ERROR":
            errCount++
        }
    }

    fmt.Println()
    fmt.Println("============================================================")
    fmt.Println("  CVE IMPACT SCAN RESULTS")
    fmt.Println("============================================================")
    fmt.Printf("  CVEs Searched            : %s%d%s\n", cCyan, len(results), cReset)
    fmt.Printf("  🔴 With Impacted Resources: %s%d%s\n", cRed, found, cReset)
    fmt.Printf("  ✅ No Impact              : %s%d%s\n", cGreen, notFound, cReset)
    fmt.Printf("  ❌ Errors                 : %s%d%s\n", cRed, errCount, cReset)
    fmt.Println("------------------------------------------------------------")
    fmt.Printf("  Total Impacted Resources : %s%d%s\n", cRed, totalRes, cReset)
    fmt.Printf("  Unique Repositories      : %s%d%s\n", cCyan, len(allRepos), cReset)
    fmt.Printf("  Unique Artifacts         : %s%d%s\n", cCyan, len(allArtifacts), cReset)
    fmt.Printf("  Unique Impacted Packages : %s%d%s\n", cCyan, len(allImpactedPkgs), cReset)

    // Repos
    if len(allRepos) > 0 && len(allRepos) <= 30 {
        fmt.Println()
        fmt.Println("  Impacted Repositories:")
        repos := make([]string, 0, len(allRepos))
        for r := range allRepos {
            repos = append(repos, r)
        }
        sort.Strings(repos)
        for _, r := range repos {
            fmt.Printf("    - %s\n", r)
        }
    }

    // Top CVEs
    if len(topCVEs) > 0 {
        fmt.Println()
        fmt.Println("  Top CVEs by Impact:")
        sort.Slice(topCVEs, func(i, j int) bool {
            return topCVEs[i].TotalResources > topCVEs[j].TotalResources
        })
        limit := 15
        if len(topCVEs) < limit {
            limit = len(topCVEs)
        }
        for i := 0; i < limit; i++ {
            r := topCVEs[i]
            repos := make(map[string]bool)
            pkgs := make(map[string]bool)
            for _, res := range r.Resources {
                repos[res.Repo] = true
                pkgs[res.ImpactedPkgVersion.Name] = true
            }
            pkgNames := make([]string, 0, len(pkgs))
            for p := range pkgs {
                pkgNames = append(pkgNames, p)
            }
            fmt.Printf("    %s%-20s%s %4d resource(s), %d repo(s) — %s\n",
                cBold, r.CVE.CVEID, cReset,
                r.TotalResources, len(repos),
                strings.Join(pkgNames, ", "))
        }

        // Top impacted packages
        fmt.Println()
        fmt.Println("  Most Widely Impacted Packages:")
        pkgCount := make(map[string]int)
        for _, r := range results {
            if r.Status == "FOUND" {
                for _, res := range r.Resources {
                    key := res.ImpactedPkgVersion.Name + "@" + res.ImpactedPkgVersion.Version
                    pkgCount[key]++
                }
            }
        }
        type pkgStat struct {
            Name  string
            Count int
        }
        var pkgStats []pkgStat
        for name, count := range pkgCount {
            pkgStats = append(pkgStats, pkgStat{name, count})
        }
        sort.Slice(pkgStats, func(i, j int) bool {
            return pkgStats[i].Count > pkgStats[j].Count
        })
        limit = 10
        if len(pkgStats) < limit {
            limit = len(pkgStats)
        }
        for i := 0; i < limit; i++ {
            fmt.Printf("    %-30s : %d occurrence(s)\n", pkgStats[i].Name, pkgStats[i].Count)
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
    fmt.Printf("  Max pages/CVE    : %d\n", c.MaxPages)
    fmt.Printf("  Time             : %s\n", elapsed.Round(time.Millisecond))
    if elapsed.Seconds() > 0 {
        fmt.Printf("  Rate             : %.1f CVEs/sec\n", float64(len(results))/elapsed.Seconds())
    }
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
    fmt.Println("  JFrog Xray — CVE Impact Scanner")
    fmt.Println("============================================================")
    fmt.Printf("  Host           : %s\n", c.Host)
    fmt.Printf("  CSV            : %s\n", c.CSVFile)
    fmt.Printf("  Output         : %s\n", c.OutputFile)
    fmt.Printf("  Workers        : %d\n", c.MaxWorkers)
    fmt.Printf("  Limit/page     : %d\n", c.Limit)
    fmt.Printf("  Max pages/CVE  : %d\n", c.MaxPages)
    fmt.Printf("  Timeout        : %ds\n", c.Timeout)
    fmt.Printf("  Debug          : %v\n", c.Debug)
    fmt.Printf("  Dry Run        : %v\n", c.DryRun)
    fmt.Println("============================================================")
    fmt.Println("  API: GET /xray/api/v2/search/impactedResources")
    fmt.Println("       ?vulnerability=<CVE>&limit=N[&last_key=<cursor>]")
    fmt.Println("  Auth: Basic (username:password)")
    fmt.Println("============================================================")
    fmt.Println()
}
