// Command probe-engine loads the local OWASP CRS fork into a Coraza WAF and
// probes HTTP requests against it, emitting matched rules and anomaly score as
// JSON. It is the engine-as-oracle used by the CRS rule-generation skills.
//
// It supports three input shapes on stdin:
//   - single  : {"request": {...}}                  -> one flat result
//   - batch    : {"requests": [{...}, {...}]}        -> results array, one WAF compile
//   - sweep    : {"request"|"requests": ..., "sweep": true} -> each request at PL1-4
//
// Usage:
//
//	echo '{"request":{"method":"GET","uri":"/?q=..."}}' | probe-engine --crs ./coreruleset
//	echo '{"requests":[...]}'                          | probe-engine --crs ./coreruleset
//	echo '{"request":{...},"sweep":true}'              | probe-engine --crs ./coreruleset
//	probe-engine --crs ./coreruleset --check        # build-only sanity check
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

//go:embed base.conf
var baseConf string

// probeScoreRuleID is a synthetic rule appended after the CRS ruleset to
// surface the final inbound anomaly score in its (macro-expanded) message. It
// is filtered out of the matched-rules output.
const probeScoreRuleID = 900100

func main() {
	crsPath := flag.String("crs", "coreruleset", "path to the CRS fork directory (contains crs-setup.conf.example and rules/)")
	paranoia := flag.Int("paranoia", 1, "CRS paranoia level (1-4); overridden by the request JSON when it sets a non-zero paranoia")
	candidateFile := flag.String("candidate-rule-file", "", "optional path to a file containing an extra SecRule to load (author parse-check)")
	check := flag.Bool("check", false, "build the WAF and report the loaded rule count, then exit (no request probing)")
	flag.Parse()

	if err := run(*crsPath, *paranoia, *candidateFile, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(crsPath string, paranoiaFlag int, candidateFile string, check bool) error {
	if check {
		if paranoiaFlag < 1 || paranoiaFlag > 4 {
			return fmt.Errorf("paranoia must be between 1 and 4, got %d", paranoiaFlag)
		}
		_, ruleCount, err := buildWAF(crsPath, paranoiaFlag, "")
		if err != nil {
			return fmt.Errorf("failed to build WAF: %w", err)
		}
		fmt.Printf("ok: CRS fork %q compiled into Coraza at PL%d, %d rules loaded\n", crsPath, paranoiaFlag, ruleCount)
		return nil
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	var input probeInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return emit(errorOutput(fmt.Sprintf("invalid input JSON: %v", err)))
	}

	paranoia := paranoiaFlag
	if input.Paranoia != 0 {
		paranoia = input.Paranoia
	}
	// In sweep mode the PL is iterated (1-4), so the configured value is moot.
	if !input.Sweep && (paranoia < 1 || paranoia > 4) {
		return emit(errorOutput(fmt.Sprintf("paranoia must be between 1 and 4, got %d", paranoia)))
	}

	candidateRule := input.CandidateRule
	if candidateFile != "" {
		b, err := os.ReadFile(candidateFile)
		if err != nil {
			return emit(errorOutput(fmt.Sprintf("reading candidate-rule-file: %v", err)))
		}
		candidateRule = string(b)
	}

	// Assemble the request list. "requests" (plural) takes precedence; a lone
	// "request" is promoted to a single-element list.
	reqs := input.Requests
	if len(reqs) == 0 && input.Request != nil {
		reqs = []probeRequest{*input.Request}
	}
	if len(reqs) == 0 {
		return emit(errorOutput(`input must provide "request" or "requests"`))
	}

	// The single-request, non-sweep path keeps the original flat output
	// contract. Anything else (batch list or sweep) emits a results array.
	if !input.Sweep && len(input.Requests) == 0 {
		return emit(probe(crsPath, paranoia, candidateRule, reqs[0]))
	}
	return emitBatch(probeBatch(crsPath, paranoia, candidateRule, reqs, input.Sweep))
}

// probe builds the WAF (optionally with a candidate rule) and runs the request
// through a transaction, returning the structured result.
//
// A build failure is classified: if a candidate rule was supplied and the base
// ruleset alone compiles, the candidate is at fault (parse_ok=false, status=ok).
// Otherwise it is an operational error such as a bad --crs path or a broken
// ruleset (status=error).
func probe(crsPath string, paranoia int, candidateRule string, req probeRequest) probeOutput {
	waf, _, err := buildWAF(crsPath, paranoia, candidateRule)
	if err != nil {
		msg := err.Error()
		if candidateRule != "" {
			if _, _, baseErr := buildWAF(crsPath, paranoia, ""); baseErr == nil {
				return probeOutput{Status: "ok", ParseOk: false, MatchedRules: []matchedRuleOut{}, Error: &msg}
			}
		}
		return errorOutput(msg)
	}

	rules, score, blocked, intr := runReq(waf, req)
	return probeOutput{
		Status:       "ok",
		ParseOk:      true,
		MatchedRules: rules,
		AnomalyScore: score,
		Blocked:      blocked,
		Interruption: intr,
	}
}

// probeBatch compiles the WAF once per paranoia level and runs every request
// through it. With sweep=false it compiles a single PL (basePL) and emits one
// result per request; with sweep=true it iterates PL1-4 so the caller can read
// the block decision per tier. A build failure is classified the same way as in
// probe (candidate parse error vs operational error).
func probeBatch(crsPath string, basePL int, candidateRule string, reqs []probeRequest, sweep bool) batchOutput {
	pls := []int{basePL}
	if sweep {
		pls = []int{1, 2, 3, 4}
	}

	out := batchOutput{Status: "ok", ParseOk: true, Results: []probeResult{}}
	for _, pl := range pls {
		waf, _, err := buildWAF(crsPath, pl, candidateRule)
		if err != nil {
			msg := err.Error()
			if candidateRule != "" {
				if _, _, baseErr := buildWAF(crsPath, pl, ""); baseErr == nil {
					return batchOutput{Status: "ok", ParseOk: false, Results: []probeResult{}, Error: &msg}
				}
			}
			return batchOutput{Status: "error", ParseOk: false, Results: []probeResult{}, Error: &msg}
		}
		for i, req := range reqs {
			rules, score, blocked, intr := runReq(waf, req)
			out.Results = append(out.Results, probeResult{
				Index:        i,
				Paranoia:     pl,
				MatchedRules: rules,
				AnomalyScore: score,
				Blocked:      blocked,
				Interruption: intr,
			})
		}
	}
	return out
}

// runReq opens a transaction on an already-built WAF, probes one request, and
// closes the transaction. The WAF is reused across calls so a batch/sweep
// compiles the ruleset only once per paranoia level.
func runReq(waf coraza.WAF, req probeRequest) ([]matchedRuleOut, anomalyScore, bool, *interruptionOut) {
	tx := waf.NewTransaction()
	defer tx.Close()
	return runTransaction(tx, req)
}

// probeInput is the stdin JSON contract. Exactly one of Request / Requests is
// expected; Requests (plural) takes precedence when both are present.
type probeInput struct {
	Request       *probeRequest  `json:"request"`
	Requests      []probeRequest `json:"requests"`
	Paranoia      int            `json:"paranoia"`
	Sweep         bool           `json:"sweep"`
	CandidateRule string         `json:"candidate_rule"`
}

type probeRequest struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Proto   string            `json:"proto"`
}

// probeOutput is the stdout JSON contract.
type probeOutput struct {
	Status       string           `json:"status"`
	ParseOk      bool             `json:"parse_ok"`
	MatchedRules []matchedRuleOut `json:"matched_rules"`
	AnomalyScore anomalyScore     `json:"anomaly_score"`
	Blocked      bool             `json:"blocked"`
	Interruption *interruptionOut `json:"interruption"`
	Error        *string          `json:"error"`
}

type matchedRuleOut struct {
	ID            int             `json:"id"`
	File          string          `json:"file,omitempty"`
	Line          int             `json:"line,omitempty"`
	Msg           string          `json:"msg"`
	Data          string          `json:"data,omitempty"`
	Phase         int             `json:"phase"`
	Severity      string          `json:"severity,omitempty"`
	Operator      string          `json:"operator,omitempty"`
	Raw           string          `json:"raw,omitempty"`
	Tags          []string        `json:"tags"`
	Maturity      int             `json:"maturity,omitempty"`
	Accuracy      int             `json:"accuracy,omitempty"`
	ParanoiaLevel int             `json:"paranoia_level"`
	Variables     []matchedVarOut `json:"variables"`
}

type matchedVarOut struct {
	Variable   string `json:"variable"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	Data       string `json:"data,omitempty"`
	ChainLevel int    `json:"chain_level"`
}

type anomalyScore struct {
	Inbound   int `json:"inbound"`
	Detection int `json:"detection"`
	Threshold int `json:"threshold"`
	ToBlock   int `json:"to_block"`
	ScorePL1  int `json:"score_pl1"`
	ScorePL2  int `json:"score_pl2"`
	ScorePL3  int `json:"score_pl3"`
	ScorePL4  int `json:"score_pl4"`
}

// probeResult is one entry in a batch/sweep result array. Index identifies the
// source request (its position in the input "requests" list, or 0 for a lone
// "request"); Paranoia is the level it was probed at.
type probeResult struct {
	Index        int              `json:"index"`
	Paranoia     int              `json:"paranoia"`
	MatchedRules []matchedRuleOut `json:"matched_rules"`
	AnomalyScore anomalyScore     `json:"anomaly_score"`
	Blocked      bool             `json:"blocked"`
	Interruption *interruptionOut `json:"interruption"`
}

// batchOutput is the stdout JSON contract for batch and sweep mode. Status,
// parse_ok and error describe the shared WAF build; results holds the per
// request (and, in sweep mode, per paranoia level) outcomes.
type batchOutput struct {
	Status  string        `json:"status"`
	ParseOk bool          `json:"parse_ok"`
	Results []probeResult `json:"results"`
	Error   *string       `json:"error"`
}

type interruptionOut struct {
	RuleID int    `json:"rule_id"`
	Action string `json:"action"`
	Status int    `json:"status"`
}

func errorOutput(msg string) probeOutput {
	return probeOutput{
		Status:       "error",
		ParseOk:      false,
		MatchedRules: []matchedRuleOut{},
		Error:        &msg,
	}
}

func emit(out probeOutput) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func emitBatch(out batchOutput) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// slashFS normalizes OS-specific path separators to forward slashes before
// delegating to the wrapped filesystem. Coraza's SecLang parser joins include
// paths with filepath.Join (parser.go), which emits backslashes on Windows and
// makes io/fs reject the path with "invalid argument". Converting on the way in
// keeps the engine portable across platforms.
type slashFS struct{ inner fs.FS }

func (s slashFS) Open(name string) (fs.File, error) {
	return s.inner.Open(filepath.ToSlash(name))
}

func (s slashFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(s.inner, filepath.ToSlash(name))
}

func (s slashFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(s.inner, filepath.ToSlash(name))
}

func (s slashFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(s.inner, filepath.ToSlash(name))
}

func (s slashFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(s.inner, filepath.ToSlash(pattern))
}

// buildWAF compiles the CRS fork at crsPath into a Coraza WAF at the given
// paranoia level. If candidateRule is non-empty it is appended as an extra
// directive (used for the author parse-check). It returns the WAF, the number
// of loaded rules, and any compilation error.
func buildWAF(crsPath string, paranoia int, candidateRule string) (coraza.WAF, int, error) {
	dataDir, err := os.MkdirTemp("", "probe-engine-data-")
	if err != nil {
		return nil, 0, fmt.Errorf("creating data dir: %w", err)
	}

	rootFS := slashFS{inner: os.DirFS(crsPath)}

	cfg := coraza.NewWAFConfig().
		WithRootFS(rootFS).
		WithDirectives(baseConf).
		WithDirectives(fmt.Sprintf("SecDataDir %s", dataDir)).
		WithDirectives(paranoiaSetup(paranoia)).
		WithDirectives("Include crs-setup.conf.example").
		WithDirectives("Include rules/*.conf").
		WithDirectives(scoreCaptureRule())

	if candidateRule != "" {
		cfg = cfg.WithDirectives(candidateRule)
	}

	ruleCount := 0
	cfg = experimental.WAFConfigWithRuleObserver(cfg, func(types.RuleMetadata) {
		ruleCount++
	})

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, 0, err
	}
	return waf, ruleCount, nil
}

// paranoiaSetup returns a SecAction that pins the CRS paranoia level. It is
// loaded before crs-setup so the CRS initialization rules honour it.
func paranoiaSetup(pl int) string {
	return fmt.Sprintf(
		"SecAction \"id:900000,phase:1,nolog,pass,t:none,"+
			"setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"",
		pl, pl,
	)
}

// scoreCaptureRule is appended after the CRS ruleset to surface the final
// inbound anomaly score and the configured blocking threshold. It always
// matches (score >= 0) and is filtered out of the matched-rules output; its
// expanded message carries both values.
func scoreCaptureRule() string {
	return fmt.Sprintf(
		"SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge 0\" "+
			"\"id:%d,phase:5,t:none,log,pass,"+
			"msg:'PROBE_SCORE=%%{tx.blocking_inbound_anomaly_score} "+
			"PROBE_THRESHOLD=%%{tx.inbound_anomaly_score_threshold} "+
			"PROBE_DETECTION=%%{tx.detection_inbound_anomaly_score} "+
			"PROBE_PL1=%%{tx.inbound_anomaly_score_pl1} "+
			"PROBE_PL2=%%{tx.inbound_anomaly_score_pl2} "+
			"PROBE_PL3=%%{tx.inbound_anomaly_score_pl3} "+
			"PROBE_PL4=%%{tx.inbound_anomaly_score_pl4}'\"",
		probeScoreRuleID,
	)
}
