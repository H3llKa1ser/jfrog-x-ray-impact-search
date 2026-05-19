# jfrog-x-ray-cve-checker

### 1) Download

    git clone https://github.com/H3llKa1ser/jfrog-x-ray-cve-checker

Then,

    cd jfrog-x-ray-cve-checker/

### 2) Compile

    go build -o x-ray_cve_check x-ray_cve_check.go

Compile for all OS

    bash build.sh

### 3) Prepare the program to use it system-wide

    sudo cp x-ray_cve_check /usr/bin/x-ray_cve_check

### 4) Run to check for CVEs

    x-ray_cve_check -csv packages.csv -host https://artifactory.mycompany.com -user USERNAME -pass PASSWORD

### 5) Filter only Critical and High vulnerabilities

    x-ray_cve_check -csv packages.csv -host https://artifactory.mycompany.com -user USERNAME -pass PASSWORD -severity Critical,High

### 6) Self-signed certificate

    x-ray_cve_check -csv packages.csv -host https://artifactory.mycompany.com -user USERNAME -pass PASSWORD -insecure
