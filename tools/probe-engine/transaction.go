package main

import (
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

// blocking rule IDs from REQUEST-949-BLOCKING-EVALUATION.conf: 949110 (phase 2)
// and 949111 (phase 1, early blocking). A match on either means the inbound
// anomaly score crossed the configured threshold.
var blockingRuleIDs = map[int]bool{949110: true, 949111: true}

const (
	scoreMsgPrefix     = "PROBE_SCORE="
	thresholdMsgPrefix = "PROBE_THRESHOLD="
	detectionMsgPrefix = "PROBE_DETECTION="
	pl1MsgPrefix       = "PROBE_PL1="
	pl2MsgPrefix       = "PROBE_PL2="
	pl3MsgPrefix       = "PROBE_PL3="
	pl4MsgPrefix       = "PROBE_PL4="
)

// runTransaction feeds a structured request through a Coraza transaction and
// returns the matched detection rules, the anomaly score (with threshold and
// distance-to-block), the block decision and any disruptive interruption.
func runTransaction(tx types.Transaction, req probeRequest) ([]matchedRuleOut, anomalyScore, bool, *interruptionOut) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	uri := req.URI
	if uri == "" {
		uri = "/"
	}

	var intr *interruptionOut

	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 0)
	tx.ProcessURI(uri, method, proto)

	hasHost := false
	for k, v := range req.Headers {
		tx.AddRequestHeader(k, v)
		if strings.EqualFold(k, "Host") {
			hasHost = true
			tx.SetServerName(v)
		}
	}
	if !hasHost {
		tx.AddRequestHeader("Host", "localhost")
		tx.SetServerName("localhost")
	}

	if it := tx.ProcessRequestHeaders(); it != nil && intr == nil {
		intr = newInterruption(it)
	}

	if req.Body != "" && tx.IsRequestBodyAccessible() {
		if it, _, err := tx.WriteRequestBody([]byte(req.Body)); err == nil && it != nil && intr == nil {
			intr = newInterruption(it)
		}
	}
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil && intr == nil {
		intr = newInterruption(it)
	}

	// Phase 5 rules (including the synthetic score-capture rule) run here.
	tx.ProcessLogging()

	rules, score, threshold, detection, pl1, pl2, pl3, pl4, blocked := collectMatches(tx)
	as := anomalyScore{
		Inbound:   score,
		Detection: detection,
		Threshold: threshold,
		ScorePL1:  pl1,
		ScorePL2:  pl2,
		ScorePL3:  pl3,
		ScorePL4:  pl4,
	}
	if threshold > score {
		as.ToBlock = threshold - score
	}
	return rules, as, blocked || intr != nil, intr
}

// collectMatches maps tx.MatchedRules() into the detection-rule list, extracting
// the inbound anomaly score and threshold from the synthetic capture rule (which
// is omitted from the list) and detecting whether a CRS blocking rule fired.
func collectMatches(tx types.Transaction) (rules []matchedRuleOut, score, threshold, detection, pl1, pl2, pl3, pl4 int, blocked bool) {
	rules = []matchedRuleOut{}
	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		id := rule.ID()

		if id == probeScoreRuleID {
			score, threshold, detection, pl1, pl2, pl3, pl4 = parseScores(mr.Message())
			continue
		}
		// Blocking-evaluation rules (949110/949111) decide blocking; that
		// semantic is already exposed via the blocked field, so record it and
		// drop the rule from the list.
		if blockingRuleIDs[id] {
			blocked = true
			continue
		}

		// Keep only genuine detection rules. CRS infrastructure that carries a
		// message but is not a detection - blocking evaluation (949), score
		// correlation (980170), initialization/admin (901xxx) - has neither a
		// paranoia-level nor an attack-* tag; silent setvar rules have no
		// message. Either condition excludes the rule.
		tags := rule.Tags()
		if strings.TrimSpace(mr.Message()) == "" || !isDetectionRule(tags) {
			continue
		}

		vars := make([]matchedVarOut, 0, len(mr.MatchedDatas()))
		for _, d := range mr.MatchedDatas() {
			vars = append(vars, matchedVarOut{
				Variable:   d.Variable().Name(),
				Key:        d.Key(),
				Value:      d.Value(),
				Data:       d.Data(),
				ChainLevel: d.ChainLevel(),
			})
		}

		if tags == nil {
			tags = []string{}
		}
		rules = append(rules, matchedRuleOut{
			ID:            id,
			File:          rule.File(),
			Line:          rule.Line(),
			Msg:           mr.Message(),
			Data:          mr.Data(),
			Phase:         int(rule.Phase()),
			Severity:      rule.Severity().String(),
			Operator:      rule.Operator(),
			Raw:           rule.Raw(),
			Tags:          tags,
			Maturity:      rule.Maturity(),
			Accuracy:      rule.Accuracy(),
			ParanoiaLevel: paranoiaLevelFromTags(tags),
			Variables:     vars,
		})
	}
	return rules, score, threshold, detection, pl1, pl2, pl3, pl4, blocked
}

const paranoiaTagPrefix = "paranoia-level/"

// isDetectionRule reports whether a rule is an actual attack-detection rule,
// identified by a paranoia-level/N tag or any attack-* tag. CRS infrastructure
// (initialization, blocking evaluation, score correlation) carries neither.
func isDetectionRule(tags []string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, paranoiaTagPrefix) || strings.HasPrefix(t, "attack-") {
			return true
		}
	}
	return false
}

// paranoiaLevelFromTags extracts N from a paranoia-level/N tag. It returns 0
// when no such tag is present (the rule is untagged for paranoia level, not
// necessarily PL1).
func paranoiaLevelFromTags(tags []string) int {
	for _, t := range tags {
		if rest, ok := strings.CutPrefix(t, paranoiaTagPrefix); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				return n
			}
		}
	}
	return 0
}

// parseScores extracts all score fields from the synthetic capture rule message.
func parseScores(msg string) (score, threshold, detection, pl1, pl2, pl3, pl4 int) {
	return parseIntField(msg, scoreMsgPrefix),
		parseIntField(msg, thresholdMsgPrefix),
		parseIntField(msg, detectionMsgPrefix),
		parseIntField(msg, pl1MsgPrefix),
		parseIntField(msg, pl2MsgPrefix),
		parseIntField(msg, pl3MsgPrefix),
		parseIntField(msg, pl4MsgPrefix)
}

// parseIntField reads the leading run of digits that follows prefix in msg.
func parseIntField(msg, prefix string) int {
	i := strings.Index(msg, prefix)
	if i < 0 {
		return 0
	}
	rest := msg[i+len(prefix):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(rest[:end])
	return n
}

func newInterruption(it *types.Interruption) *interruptionOut {
	if it == nil {
		return nil
	}
	return &interruptionOut{
		RuleID: it.RuleID,
		Action: it.Action,
		Status: it.Status,
	}
}
