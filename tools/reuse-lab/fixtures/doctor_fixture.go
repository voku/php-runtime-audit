package main

// This is CI-only first-party comparison code compiled against a pinned,
// separately downloaded upstream module. No package mutation or host scanning.
import (
    "encoding/json"
    "fmt"
    "os"
    "time"

    "github.com/andreysheva/php2shell-doctor/internal/model"
    "github.com/andreysheva/php2shell-doctor/internal/stale"
    "github.com/andreysheva/php2shell-doctor/internal/vendordb"
)

type vendorCase struct {
    ID string `json:"id"`
    Vendor string `json:"vendor"`
    Package string `json:"package"`
    Version string `json:"version"`
    RPM bool `json:"rpm"`
    ExpectedDoctor string `json:"expected_doctor"`
    DesiredProduct string `json:"desired_product"`
}
type workerCase struct {
    ID string `json:"id"`
    InstalledPath string `json:"installed_path"`
    WorkerPath string `json:"worker_path"`
    WorkerStarted string `json:"worker_started"`
    BinaryModified string `json:"binary_modified"`
    ExpectedChecked int `json:"expected_doctor_checked"`
    ExpectedStale int `json:"expected_doctor_stale"`
    DesiredProduct string `json:"desired_product"`
}
type fixtures struct {
    SchemaVersion int `json:"schema_version"`
    OfficialSource string `json:"official_source"`
    Vendors []vendorCase `json:"vendor_cases"`
    Workers []workerCase `json:"worker_cases"`
}
type observation struct {
    ID string `json:"id"`
    Group string `json:"group"`
    Observed string `json:"observed_doctor"`
    Expected string `json:"expected_doctor"`
    Desired string `json:"desired_product"`
    ProductGap bool `json:"needs_product_adapter"`
}
func mustTime(raw string) time.Time {
    t, err := time.Parse(time.RFC3339, raw)
    if err != nil { panic(err) }
    return t
}
func main() {
    if len(os.Args) != 2 { fmt.Fprintln(os.Stderr, "expected one fixtures JSON path"); os.Exit(2) }
    raw, err := os.ReadFile(os.Args[1])
    if err != nil { panic(err) }
    var spec fixtures
    if err := json.Unmarshal(raw, &spec); err != nil { panic(err) }
    if spec.SchemaVersion != 1 || len(spec.Vendors)<3 || len(spec.Workers)<3 {panic("incomplete fixture manifest")}
    db, err := vendordb.Embedded()
    if err != nil { panic(err) }
    var observations []observation
    unexpected := 0
    gaps := 0
    for _, c := range spec.Vendors {
        got, _ := db.PackageVerdict(c.Vendor, c.Package, c.Version, c.RPM)
        observed := got.String()
        if observed != c.ExpectedDoctor { unexpected++ }
        productGap := (c.ID=="jammy-php81-before-fixed" || c.ID=="jammy-php81-fixed") && observed=="VERIFY_VENDOR"
        if productGap { gaps++ }
        observations=append(observations, observation{c.ID,"vendor",observed,c.ExpectedDoctor,c.DesiredProduct,productGap})
    }
    for _, c := range spec.Workers {
        inst := model.InstallReport{
            Verdict: model.VerdictPatched,
            Install: model.Install{BinaryPath:c.InstalledPath,BinaryMtime:mustTime(c.BinaryModified)},
        }
        processes := []model.ProcessInfo{{PID:4242,Name:"php-fpm",ExePath:c.WorkerPath,Started:mustTime(c.WorkerStarted)}}
        result := stale.Check(inst,processes)
        observed := fmt.Sprintf("checked=%d,stale=%d",result.Checked,len(result.StaleProcesses))
        expected := fmt.Sprintf("checked=%d,stale=%d",c.ExpectedChecked,c.ExpectedStale)
        if observed != expected {unexpected++}
        productGap := result.Checked == 0 || (result.Checked > 0 && len(result.StaleProcesses)==0)
        if productGap { gaps++ }
        observations=append(observations, observation{c.ID,"worker",observed,expected,c.DesiredProduct,productGap})
    }
    output := struct {
        SchemaVersion int `json:"schema_version"`
        Source string `json:"official_source"`
        Observations []observation `json:"observations"`
        Unexpected int `json:"unexpected_mismatches"`
        AdapterGaps int `json:"product_adapter_gaps"`
        Meaning string `json:"meaning"`
    }{1,spec.OfficialSource, observations, unexpected,gaps,
        "Upstream behavior compared to explicit expected product semantics; adapter gaps are not proof of upstream bugs. Local PRA-4 code was not executed."}
    b, err := json.MarshalIndent(output, "", "  ")
    if err != nil {panic(err)}
    fmt.Println(string(b))
    if unexpected != 0 {os.Exit(1)}
}
