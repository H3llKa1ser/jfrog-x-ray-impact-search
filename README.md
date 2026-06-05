# jfrog-x-ray-impact-search

### 1) Download

    git clone https://github.com/H3llKa1ser/jfrog-x-ray-impact-search

Then,

    cd jfrog-x-ray-impact-search/

### 2) Compile

    go build -o x-ray_impact_search x-ray_impact_search.go

Compile for all OS

    bash build.sh

### 3) Make it executable

    chmod +x x-ray_impact_search

### 4) Prepare the program to use it system-wide

    sudo cp x-ray_impact_search /usr/bin/x-ray_impact_search

### 5) Search by CVE/XRAY IDs

    ./x-ray_impact_search -csv cves.csv -mode vulnerability -host https://jfrog.company.tech -user admin -pass secret

### 6) Search by packages (your original CSV format)

    ./x-ray_impact_search -csv packages.csv -mode package -host https://jfrog.company.tech -user admin -pass secret

### 7) Auto-detect mode

    ./x-ray_impact_search -csv input.csv -host https://jfrog.company.tech -user admin -pass secret

### 8) Dry run

    ./x-ray_impact_search -csv packages.csv -mode package -dry-run

### 9) Debug

    ./x-ray_impact_search -csv cves.csv -mode vulnerability -debug

## 10) Help

    ./x-ray_impact_search
