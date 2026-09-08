package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// maxSlackFindings bounds how many findings are listed in a message.
// A scan of a large image can introduce hundreds; Slack renders a wall
// of them badly and rejects oversized payloads outright. The count in
// the header is always the true total, so nothing is hidden -- the
// message says how many more there are.
const maxSlackFindings = 10

// SlackNotifier posts the event to a Slack incoming webhook URL.
// Deliberately incoming-webhook only, no OAuth: the URL is the entire
// credential, which keeps this to one config field and no token refresh.
type SlackNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewSlack(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: webhookTimeout},
	}
}

func (s *SlackNotifier) Notify(ctx context.Context, event ScanEvent) error {
	body, err := json.Marshal(s.buildMessage(event))
	if err != nil {
		return fmt.Errorf("encode slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Error("notify: slack delivery failed", "artifact_id", event.ArtifactID, "err", err)
		return fmt.Errorf("post to slack: %w", err)
	}
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	// Slack answers 200 with a plain-text body ("ok", or an error like
	// "invalid_payload"/"no_service") rather than a status code you can
	// switch on, so the body is the only way to tell a delivered
	// message from a rejected one.
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(payload)) != "ok" {
		err := fmt.Errorf("slack returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
		slog.Error("notify: slack delivery failed", "artifact_id", event.ArtifactID, "err", err)
		return err
	}
	return nil
}

// buildMessage renders the standard Slack blocks payload. text is set
// as well as blocks: it's what Slack shows in notifications and on
// clients that can't render blocks, and omitting it produces a
// notification that just says "attachment".
func (s *SlackNotifier) buildMessage(event ScanEvent) map[string]any {
	// A component event carries no findings and no severity, so the
	// findings renderer below would head it "0 new  finding(s)". Its
	// own message rather than conditionals threaded through that one:
	// the two events say different things and share only the artifact.
	if len(event.NewFindings) == 0 && len(event.NewComponents) > 0 {
		return s.buildComponentMessage(event)
	}
	summary := fmt.Sprintf("%s: %d new %s finding(s) on %s",
		strings.ToUpper(event.Severity), len(event.NewFindings), strings.ToLower(event.Severity), event.ArtifactRef)
	// KEV leads. Exploitation observed in the wild outranks any
	// predicted severity, and it is the single fact that decides
	// whether this is worth interrupting someone for -- so it goes in
	// front of the severity summary rather than being something the
	// reader has to find in a list of twenty findings.
	if event.KnownExploitedCount > 0 {
		summary = fmt.Sprintf("KNOWN EXPLOITED: %d of %d new finding(s) on %s are in CISA's KEV catalog",
			event.KnownExploitedCount, len(event.NewFindings), event.ArtifactRef)
	}

	var lines []string
	for i, f := range event.NewFindings {
		if i == maxSlackFindings {
			lines = append(lines, fmt.Sprintf("_…and %d more_", len(event.NewFindings)-maxSlackFindings))
			break
		}
		line := fmt.Sprintf("• *%s* (%s)", f.ID, f.Severity)
		if f.KnownExploited {
			line += "  *[KNOWN EXPLOITED]*"
		}
		if f.EPSSScore > 0 {
			line += fmt.Sprintf("  _EPSS %.1f%%_", f.EPSSScore*100)
		}
		if f.Title != "" {
			line += " — " + f.Title
		}
		if f.Source != "" {
			line += fmt.Sprintf("  _[%s]_", f.Source)
		}
		lines = append(lines, line)
	}

	return map[string]any{
		"text": summary,
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf("%d new %s finding(s)", len(event.NewFindings), strings.ToLower(event.Severity)),
				},
			},
			{
				"type": "section",
				"fields": []map[string]any{
					{"type": "mrkdwn", "text": "*Artifact:*\n" + event.ArtifactRef},
					{"type": "mrkdwn", "text": "*Worst severity:*\n" + event.Severity},
				},
			},
			{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": strings.Join(lines, "\n")},
			},
			{
				"type": "context",
				"elements": []map[string]any{
					{"type": "mrkdwn", "text": "artifact `" + event.ArtifactID + "` • supply-chain-monitor"},
				},
			},
		},
	}
}

// buildComponentMessage renders the "new packages appeared in this
// artifact" event. Deliberately quieter in tone than the findings
// message -- nothing here is known to be wrong, and most of these are
// an ordinary base-image bump. What it is for is the case that has no
// finding at all: a package that arrived without anyone adding it.
func (s *SlackNotifier) buildComponentMessage(event ScanEvent) map[string]any {
	summary := fmt.Sprintf("%d new component(s) in %s", len(event.NewComponents), event.ArtifactRef)

	var lines []string
	for i, c := range event.NewComponents {
		if i == maxSlackFindings {
			lines = append(lines, fmt.Sprintf("_…and %d more_", len(event.NewComponents)-maxSlackFindings))
			break
		}
		line := "• *" + c.PURL + "*"
		if c.Licenses != "" {
			line += fmt.Sprintf("  _[%s]_", c.Licenses)
		}
		lines = append(lines, line)
	}

	return map[string]any{
		"text": summary,
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf("%d new component(s)", len(event.NewComponents)),
				},
			},
			{
				"type": "section",
				"fields": []map[string]any{
					{"type": "mrkdwn", "text": "*Artifact:*\n" + event.ArtifactRef},
				},
			},
			{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": strings.Join(lines, "\n")},
			},
			{
				"type": "context",
				"elements": []map[string]any{
					{"type": "mrkdwn", "text": "artifact `" + event.ArtifactID + "` • supply-chain-monitor"},
				},
			},
		},
	}
}
