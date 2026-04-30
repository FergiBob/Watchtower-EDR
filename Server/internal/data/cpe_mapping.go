package data

import (
	"Watchtower_EDR/server/internal/logs"
	"Watchtower_EDR/shared"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blugelabs/bluge"
)

// SearchEngine wraps the Bluge writer and configuration
type SearchEngine struct {
	path   string
	config bluge.Config
	Writer *bluge.Writer
}

var GlobalSearchEngine *SearchEngine

// NewSearchEngine initializes the configuration for the index directory
func NewSearchEngine(indexPath string) *SearchEngine {
	cfg := bluge.DefaultConfig(indexPath)

	writer, err := bluge.OpenWriter(cfg)
	if err != nil {
		logs.Map.Error("Failed to initialize Bluge writer", "path", indexPath, "error", err)
		os.Exit(1)
	}

	engine := &SearchEngine{
		path:   indexPath,
		config: cfg,
		Writer: writer,
	}
	GlobalSearchEngine = engine
	return engine
}

func (s *SearchEngine) GetWriter() (*bluge.Writer, error) {
	if s.Writer == nil {
		return nil, fmt.Errorf("index writer not initialized")
	}
	return s.Writer, nil
}

// --- SEARCH LOGIC ---

// Search finds the best matching CPE URI based on automated logic, prioritizing version matches.
func (s *SearchEngine) Search(vendor, product, version string) (string, float64, error) {
	reader, err := bluge.OpenReader(s.config)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open reader: %w", err)
	}
	defer reader.Close()

	pSearch := SanitizeAndClean(product)
	vSearch := SanitizeAndClean(vendor)

	if len(pSearch) < 2 {
		return "", 0, fmt.Errorf("search string too short")
	}

	// Root Boolean Query
	bq := bluge.NewBooleanQuery()

	// PRODUCT: Required Anchor (Must match at least one word)
	productMatch := bluge.NewMatchQuery(pSearch).
		SetField("product").
		SetOperator(bluge.MatchQueryOperatorOr).
		SetBoost(2.5) // Primary weight
	bq.AddMust(productMatch)

	// VENDOR: Strong Context (High Boost if matches)
	if vSearch != "" && vSearch != "unknown" {
		vendorMatch := bluge.NewMatchQuery(vSearch).
			SetField("vendor").
			SetBoost(1.8)
		bq.AddShould(vendorMatch)
	}

	// VERSION: Multi-Tiered Fallback
	// We use nested SHOULD queries to prioritize exact matches over generic ones
	versionQuery := bluge.NewBooleanQuery()

	if version != "" && version != "-" && version != "*" {
		// Tier A: Exact version match (Highest Priority)
		exactVer := bluge.NewMatchQuery(version).
			SetField("version").
			SetBoost(1.5)
		versionQuery.AddShould(exactVer)

		// Tier B: Generic fallback (*)
		// This allows the search to succeed if the specific version isn't indexed
		anyVer := bluge.NewMatchQuery("*").SetField("version").SetBoost(0.5)
		noneVer := bluge.NewMatchQuery("-").SetField("version").SetBoost(0.5)
		versionQuery.AddShould(anyVer)
		versionQuery.AddShould(noneVer)
	} else {
		// If agent provides no version, prioritize the generic CPEs
		genericOnly := bluge.NewMatchQuery("*").SetField("version")
		versionQuery.AddShould(genericOnly)
	}

	bq.AddShould(versionQuery)

	// Execute Search
	request := bluge.NewTopNSearch(1, bq)
	documentMatchIterator, err := reader.Search(context.Background(), request)
	if err != nil {
		return "", 0, err
	}

	match, err := documentMatchIterator.Next()
	if err != nil || match == nil {
		return "", 0, fmt.Errorf("no match found")
	}

	// Threshold check (Score will be higher if version matches, lower if fallback used)
	if match.Score < 1.0 {
		return "", 0, fmt.Errorf("quality below threshold")
	}

	var foundCPE string
	match.VisitStoredFields(func(field string, value []byte) bool {
		if field == "_id" {
			foundCPE = string(value)
		}
		return true
	})

	return foundCPE, match.Score, nil
}

// ManualSearch allows the Web GUI to "browse" the dictionary for user selection.
// It performs a broad search on Product/Vendor and filters results by Version in Go for higher accuracy.
func (s *SearchEngine) ManualSearch(pQuery, vQuery, verQuery string, limit int) ([]map[string]string, error) {
	reader, err := bluge.OpenReader(s.config)
	if err != nil {
		return nil, fmt.Errorf("failed to open reader: %w", err)
	}
	defer reader.Close()

	results := make([]map[string]string, 0)
	bq := bluge.NewBooleanQuery()
	anyCriteria := false

	if pQuery != "" {
		anyCriteria = true
		cleanP := strings.ToLower(strings.TrimSpace(pQuery))
		searchProduct := strings.ReplaceAll(cleanP, " ", "_")

		prodMatch := bluge.NewMatchQuery(searchProduct).SetField("product")

		// --- ADAPTIVE LOGIC ---
		if limit <= 1 {
			// AUTOMATION MODE: Must match every word (Strict)
			prodMatch.SetOperator(bluge.MatchQueryOperatorAnd).SetBoost(5.0)
			bq.AddMust(prodMatch)
		} else {
			// USER UI MODE: Match any word (Loose/Helpful)
			prodMatch.SetOperator(bluge.MatchQueryOperatorOr).SetBoost(2.0)
			bq.AddShould(prodMatch)
			bq.SetMinShould(1)
		}
	}

	if vQuery != "" && strings.ToLower(vQuery) != "unknown" {
		anyCriteria = true
		cleanV := strings.ToLower(strings.TrimSpace(vQuery))
		vendorMatch := bluge.NewMatchQuery(cleanV).SetField("vendor")

		if limit <= 1 {
			bq.AddMust(vendorMatch) // Automation: Vendor must match if provided
		} else {
			bq.AddShould(vendorMatch) // UI: Vendor just helps rank better
		}
	}

	if !anyCriteria {
		return results, nil
	}

	// We still pull a large pool for the Go-side version filter to work its magic
	request := bluge.NewTopNSearch(500, bq)
	iterator, err := reader.Search(context.Background(), request)
	if err != nil {
		return results, err
	}

	userVer := strings.ToLower(strings.TrimSpace(verQuery))
	match, err := iterator.Next()
	for err == nil && match != nil {
		res := make(map[string]string)
		match.VisitStoredFields(func(field string, value []byte) bool {
			if field == "name" {
				res["cpe_uri"] = string(value)
			} else {
				res[field] = string(value)
			}
			return true
		})

		// --- VERSION FILTERING ---
		itemVer := strings.ToLower(res["version"])
		keepResult := false

		if userVer == "" || userVer == "*" || userVer == "-" {
			keepResult = true
		} else {
			// We allow partial version matches (e.g. "12" matches "12.0.1")
			if itemVer == "*" || itemVer == "-" || strings.Contains(itemVer, userVer) || strings.Contains(userVer, itemVer) {
				keepResult = true
			}
		}

		if keepResult {
			results = append(results, map[string]string{
				"vendor":  res["vendor"],
				"product": res["product"],
				"version": res["version"],
				"cpe_uri": res["cpe_uri"],
			})
		}

		if len(results) >= limit {
			break
		}
		match, err = iterator.Next()
	}

	return results, nil
}

// MapCPEs performs the matching logic with a strict hierarchy: Manual > Automated
func MapCPEs(ctx context.Context, engine *SearchEngine) error {
	type swUpdate struct {
		id     int
		cpe    any
		mapped int
	}
	var swTasks []swUpdate

	swRows, err := ReadQuery(Main_Read_Database, `SELECT id, name, version, vendor FROM software WHERE mapped = 0`)
	if err != nil {
		return err
	}
	defer swRows.Close()

	for swRows.Next() {
		var id int
		var name, version, vendor string
		if err := swRows.Scan(&id, &name, &version, &vendor); err != nil {
			continue
		}

		// 1. CHECK MANUAL OVERRIDES (Highest Priority)
		var manualCPE *string
		err := QuerySingleRow(Main_Database,
			"SELECT selected_cpe FROM software_mappings WHERE raw_name = ? AND raw_vendor = ? AND raw_version = ?",
			[]any{name, vendor, version}, &manualCPE)

		if err == nil {
			swTasks = append(swTasks, swUpdate{id: id, cpe: manualCPE, mapped: 1})
			continue
		}

		// 2. GENERATE CANDIDATES (Same as Manual Search)
		// We ask for the top 5 candidates.
		candidates, err := engine.ManualSearch(name, vendor, version, 5)
		if err != nil || len(candidates) == 0 {
			continue
		}

		// 3. APPLY AUTOMATION GATEKEEPERS
		bestMatch := candidates[0] // We only ever auto-map the #1 result

		cleanName := SanitizeAndClean(name)
		cleanVendor := SanitizeAndClean(vendor)

		// GATE 1: Semantic Overlap (Name Check)
		if !isValidSemanticMatch(cleanName, bestMatch["cpe_uri"]) {
			continue
		}

		// GATE 2: Vendor Check
		// Ensure the vendor in the CPE isn't a total mismatch
		cpeVendor := strings.ToLower(bestMatch["vendor"])
		if cleanVendor != "" && cleanVendor != "unknown" {
			// If we have a vendor, it must be part of the CPE vendor or vice-versa
			if !strings.Contains(cpeVendor, cleanVendor) && !strings.Contains(cleanVendor, cpeVendor) {
				continue
			}
		}

		// GATE 3: Version Solidity
		itemVer := strings.ToLower(bestMatch["version"])
		userVer := strings.ToLower(strings.TrimSpace(version))

		versionIsSolid := false
		// Only auto-map if versions are identical or NIST uses a wildcard
		if userVer == "" || itemVer == "*" || itemVer == "-" || itemVer == userVer {
			versionIsSolid = true
		}

		if versionIsSolid {
			swTasks = append(swTasks, swUpdate{id: id, cpe: bestMatch["cpe_uri"], mapped: 1})
		}
	}

	// Perform batch update
	for _, task := range swTasks {
		WriteQuery(Main_Database, "UPDATE software SET cpe_uri = ?, mapped = ? WHERE id = ?", task.cpe, task.mapped, task.id)
	}
	return nil
}

// writes manual cpe entries to corresponding tables
func HandleManualCPEMatch(id, cpe string) {
	var cpeValue interface{}
	cpeValue = cpe

	// If the cpe string is empty, we want to store a literal NULL in the database
	// This allows your scanners to distinguish between "Not Yet Checked" and "Confirmed No CPE"
	if cpe == "" {
		cpeValue = nil
	}

	var name, vendor, version string

	WriteQuery(Main_Database,
		"UPDATE software SET cpe_uri = ?, mapped = 1 WHERE id = ?",
		cpeValue, id)

	QuerySingleRow(Main_Read_Database,
		"SELECT name, vendor, version FROM software where id = ?",
		[]any{id}, name, vendor, version)

	WriteQuery(Main_Database,
		"INSERT OR REPLACE INTO software_mappings (raw_name, raw_vendor, raw_version, selected_cpe) VALUES (?, ?, ?, ?)",
		name, vendor, version, cpeValue)

}

func SanitizeAndClean(input string) string {
	input = strings.ToLower(input)
	input = strings.ReplaceAll(input, "®", "")
	input = strings.ReplaceAll(input, "™", "")
	input = strings.ReplaceAll(input, "(x64)", "")
	input = strings.ReplaceAll(input, "(x86)", "")

	clutter := []string{"corporation", "inc", "incorporated", "ltd", "limited", "software", "systems", "technologies", "apps for enterprise", "update", "service pack", "redistributable"}
	for _, word := range clutter {
		input = strings.ReplaceAll(input, word, "")
	}

	reg := regexp.MustCompile(`[^a-z0-9\s]`)
	input = reg.ReplaceAllString(input, "")
	return strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(input, " "))
}

func isValidSemanticMatch(cleanName, cpeURI string) bool {
	parts := strings.Split(cpeURI, ":")
	if len(parts) < 5 {
		return false
	}

	// cpeProduct: "free_download_manager" -> ["free", "download", "manager"]
	cpeProductPart := strings.ReplaceAll(parts[4], "_", " ")
	cpeWords := strings.Fields(cpeProductPart)
	swWords := strings.Fields(cleanName)

	if len(cpeWords) == 0 || len(swWords) == 0 {
		return false
	}

	matchCount := 0
	for _, cw := range cpeWords {
		if len(cw) < 3 {
			continue
		} // Skip noise like "of" or "the"
		for _, sw := range swWords {
			if sw == cw {
				matchCount++
				break
			}
		}
	}

	// 1. Ratio of CPE words found in Software Name
	// Prevents "Manager" (CPE) matching "Free Download Manager" (SW)
	cpeRatio := float64(matchCount) / float64(len(cpeWords))

	// 2. Ratio of Software words found in CPE
	// Prevents "Office" (CPE) matching "Office 365 Pro Plus" (SW)
	swRatio := float64(matchCount) / float64(len(swWords))

	// STRICT: At least 75% of CPE words must hit, and 60% of SW words must hit.
	return cpeRatio >= 0.75 && swRatio >= 0.60
}

func CheckIfKnownProduct(name, vendor string) bool {
	var count int
	err := QuerySingleRow(Main_Database, "SELECT COUNT(*) FROM software_mappings WHERE raw_name = ? AND raw_vendor = ?", []any{name, vendor}, &count)
	return err == nil && count > 0
}

func (s *SearchEngine) IndexCPEs(ctx context.Context, cpeData []map[string]string) error {
	var products []CPEProduct
	for _, entry := range cpeData {
		p := CPEProduct{}
		p.CPE.CpeName = entry["cpe_uri"]
		if val, ok := entry["deprecated"]; ok && val == "true" {
			p.CPE.Deprecated = true
		}
		products = append(products, p)
	}
	if len(products) == 0 {
		return nil
	}
	if err := UpdateIndexBatch(s, products); err != nil {
		return err
	}
	return MarkItemsAsIndexed(products)
}

func UpdateIndexBatch(engine *SearchEngine, products []CPEProduct) error {
	writer, err := engine.GetWriter()
	if err != nil {
		return err
	}
	batch := bluge.NewBatch()
	for _, p := range products {
		docID := p.CPE.CpeName
		if docID == "" {
			continue
		}
		parts := strings.Split(docID, ":")
		vendor, product, version := "", "", ""
		if len(parts) > 3 {
			vendor = parts[3]
		}
		if len(parts) > 4 {
			product = parts[4]
		}
		if len(parts) > 5 {
			version = parts[5]
		}

		doc := bluge.NewDocument(docID).
			AddField(bluge.NewTextField("vendor", strings.ToLower(vendor)).StoreValue()).
			AddField(bluge.NewTextField("product", strings.ToLower(product)).StoreValue()).
			AddField(bluge.NewTextField("version", version).StoreValue()).
			AddField(bluge.NewTextField("name", docID).StoreValue())

		batch.Update(doc.ID(), doc)
	}
	return writer.Batch(batch)
}

func StartCPEMapper(ctx context.Context, engine *SearchEngine) {
	ticker := time.NewTicker(5 * time.Minute)
	WG.Add(1)
	go func() {
		defer ticker.Stop()
		defer WG.Done()
		time.Sleep(10 * time.Second)
		MapCPEs(ctx, engine)
		for {
			select {
			case <-ticker.C:
				MapCPEs(ctx, engine)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// MarkItemsAsIndexed flags records in SQLite to prevent re-processing
func MarkItemsAsIndexed(products []CPEProduct) error {
	tx, err := CPE_Database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("UPDATE cpe_dictionary SET is_indexed = 1 WHERE cpe_uri = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, p := range products {
		_, err := stmt.Exec(p.CPE.CpeName)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func GetUnindexedFromDB(limit int) ([]CPEProduct, error) {
	rows, err := CPE_Database.Query("SELECT cpe_uri FROM cpe_dictionary WHERE is_indexed = 0 LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []CPEProduct
	for rows.Next() {
		var p CPEProduct
		if err := rows.Scan(&p.CPE.CpeName); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, nil
}

func RunIndexRepair(ctx context.Context, engine *SearchEngine) {
	const batchSize = 5000
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		products, err := GetUnindexedFromDB(batchSize)
		if err != nil {
			logs.Map.Error("Repair Worker: Failed to query unindexed records", "error", err)
			return
		}
		if len(products) == 0 {
			break
		}
		if err := UpdateIndexBatch(engine, products); err != nil {
			logs.Map.Error("Repair Worker: Indexing failed", "error", err)
			return
		}
		if err := MarkItemsAsIndexed(products); err != nil {
			logs.Map.Error("Repair Worker: Failed to mark items as indexed", "error", err)
			return
		}
		logs.Map.Info("Repair Worker: Successfully indexed pending records", "count", len(products))
	}
}

// InitializeCPEIndex performs the initial high-speed bulk load
func InitializeCPEIndex(ctx context.Context, engine *SearchEngine) error {
	writer, err := bluge.OpenWriter(engine.config)
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = CPE_Database.Exec("UPDATE cpe_dictionary SET is_indexed = 0")
	if err != nil {
		logs.Map.Error("Failed to reset index status during hydration", "error", err)
		return err
	}

	rows, err := ReadQuery(CPE_Read_Database, `SELECT cpe_uri, vendor, product, version FROM cpe_dictionary WHERE deprecated = 0`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("initialization interrupted")
		default:
		}

		var uri, v, p, ver string
		if err := rows.Scan(&uri, &v, &p, &ver); err == nil {
			doc := bluge.NewDocument(uri)
			doc.AddField(bluge.NewTextField("vendor", strings.ToLower(v)).StoreValue())
			doc.AddField(bluge.NewTextField("product", strings.ToLower(p)).StoreValue())
			doc.AddField(bluge.NewTextField("version", ver).StoreValue())
			// CRITICAL: Name field allows searching the raw CPE string as a fallback
			doc.AddField(bluge.NewTextField("name", uri).StoreValue())

			writer.Insert(doc)
			count++
			if count%50000 == 0 {
				fmt.Printf("Bulk Indexing: %d entries completed...\n", count)
			}
		}
	}

	_, err = CPE_Database.Exec("UPDATE cpe_dictionary SET is_indexed = 1")
	fmt.Println("Done Indexing CPE Database!")
	return err
}

func SearchDictionaryForOSCPE(agentID string, info shared.OSInfo) {
	var cpeURI string
	cleanInfo := CleanOSData(info)
	query := `SELECT cpe_uri FROM cpe_dictionary 
		  WHERE vendor = ? AND product LIKE ? AND deprecated = 0
		  AND (version = ? OR version = ? OR version = '-' OR version = '*')
		  AND (cpe_uri LIKE ? OR cpe_uri LIKE '%:*:*:*') 
		  ORDER BY (version = ?) DESC, (version = ?) DESC, (cpe_uri LIKE ?) DESC, version DESC LIMIT 1`
	archPattern := "%:" + cleanInfo.Architecture + ":%"
	err := QuerySingleRow(CPE_Read_Database, query,
		[]any{cleanInfo.Vendor, "%" + cleanInfo.OSName + "%", cleanInfo.OSVersion, cleanInfo.OSBuild, archPattern, cleanInfo.OSVersion, cleanInfo.OSBuild, archPattern},
		&cpeURI)
	if err == nil && cpeURI != "" {
		WriteQuery(Main_Database, `UPDATE agents SET os_cpe_uri = ? WHERE agent_id = ?`, cpeURI, agentID)
	}
}

func CleanOSData(info shared.OSInfo) shared.OSInfo {
	cleanedInfo := info
	vendorInput := strings.ToLower(info.Vendor)
	vendorFields := strings.Fields(vendorInput)
	cleanVendor := "unknown"
	if len(vendorFields) > 0 {
		reg := regexp.MustCompile(`[^a-z0-9]`)
		cleanVendor = reg.ReplaceAllString(vendorFields[0], "")
	}
	p := strings.ToLower(info.OSName)
	p = strings.ReplaceAll(p, "microsoft", "")
	p = strings.ReplaceAll(p, vendorInput, "")
	editions := []string{"home", "pro", "enterprise", "education", "ultimate", "workstation"}
	for _, edition := range editions {
		p = strings.ReplaceAll(p, edition, "")
	}
	p = strings.TrimSpace(p)
	if cleanVendor == "microsoft" && strings.Contains(p, "windows") {
		lowerVersion := strings.ToLower(info.OSVersion)
		if !strings.Contains(p, lowerVersion) {
			p = p + " " + lowerVersion
		}
	}
	finalProduct := strings.ReplaceAll(p, " ", "_")
	reg2 := regexp.MustCompile(`_+`)
	finalProduct = reg2.ReplaceAllString(finalProduct, "_")
	finalProduct = strings.Trim(finalProduct, "_")
	cleanedInfo.OSName = finalProduct
	cleanedInfo.Vendor = cleanVendor
	return cleanedInfo
}
