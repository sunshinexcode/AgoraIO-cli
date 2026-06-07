package cli

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const redactedWebhookSecret = "********"

var webhookSecretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{7,32}$`)
var webhookEventKeyInvalidChars = regexp.MustCompile(`[^a-z0-9]+`)

type webhookEvent struct {
	ID          int    `json:"id"`
	Key         string `json:"key"`
	DisplayName string `json:"displayName"`
	EventType   int    `json:"eventType"`
	Payload     string `json:"payload,omitempty"`
}

type webhookConfig struct {
	ConfigID       int            `json:"configId"`
	URL            string         `json:"url"`
	URLRegion      string         `json:"urlRegion"`
	Enabled        bool           `json:"enabled"`
	EventIDs       []int          `json:"eventIds"`
	Events         []webhookEvent `json:"events,omitempty"`
	Retry          *bool          `json:"retry,omitempty"`
	UseIPWhitelist bool           `json:"useIpWhitelist"`
	Secret         string         `json:"secret,omitempty"`
}

type ncsEventListResponse struct {
	Items []ncsEvent `json:"items"`
}

type ncsEvent struct {
	EventID       int    `json:"eventId"`
	DisplayName   string `json:"displayName"`
	DisplayNameCn string `json:"displayNameCn"`
	EventType     int    `json:"eventType"`
	Payload       string `json:"payload"`
}

type ncsConfigListResponse struct {
	Items []ncsConfig `json:"items"`
}

type ncsConfig struct {
	ConfigID       int    `json:"configId"`
	URL            string `json:"url"`
	URLRegion      string `json:"urlRegion"`
	Enabled        bool   `json:"enabled"`
	EventIDs       []int  `json:"eventIds"`
	Retry          *bool  `json:"retry"`
	UseIPWhitelist bool   `json:"useIpWhitelist"`
	Secret         string `json:"secret"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

func webhookEventKey(displayName string) string {
	key := strings.ToLower(strings.TrimSpace(displayName))
	key = webhookEventKeyInvalidChars.ReplaceAllString(key, "-")
	return strings.Trim(key, "-")
}

func normalizeWebhookEvents(resp ncsEventListResponse) []webhookEvent {
	events := make([]webhookEvent, 0, len(resp.Items))
	for _, item := range resp.Items {
		events = append(events, webhookEvent{
			ID:          item.EventID,
			Key:         webhookEventKey(item.DisplayName),
			DisplayName: item.DisplayName,
			EventType:   item.EventType,
			Payload:     item.Payload,
		})
	}
	return events
}

func normalizeWebhookConfig(item ncsConfig, events []webhookEvent) webhookConfig {
	eventsByID := make(map[int]webhookEvent, len(events))
	for _, event := range events {
		eventsByID[event.ID] = event
	}

	matchedEvents := make([]webhookEvent, 0, len(item.EventIDs))
	for _, id := range item.EventIDs {
		if event, ok := eventsByID[id]; ok {
			matchedEvents = append(matchedEvents, event)
		}
	}

	eventIDs := append([]int(nil), item.EventIDs...)
	return webhookConfig{
		ConfigID:       item.ConfigID,
		URL:            item.URL,
		URLRegion:      item.URLRegion,
		Enabled:        item.Enabled,
		EventIDs:       eventIDs,
		Events:         matchedEvents,
		Retry:          item.Retry,
		UseIPWhitelist: item.UseIPWhitelist,
		Secret:         item.Secret,
	}
}

func redactWebhookConfigSecret(cfg webhookConfig, reveal bool) webhookConfig {
	if reveal || cfg.Secret == "" {
		return cfg
	}
	cfg.Secret = redactedWebhookSecret
	return cfg
}

func selectCreatedWebhookConfig(resp ncsConfigListResponse, url, urlRegion string, eventIDs []int, secret string) (ncsConfig, error) {
	matchesRequestedShape := func(item ncsConfig) bool {
		return item.URL == url &&
			item.URLRegion == urlRegion &&
			webhookIntSetEqual(item.EventIDs, eventIDs)
	}

	if secret != "" {
		if match, ok := bestWebhookConfigCandidate(resp.Items, func(item ncsConfig) bool {
			return item.Secret == secret && matchesRequestedShape(item)
		}); ok {
			return match, nil
		}
	}

	if match, ok := bestWebhookConfigCandidate(resp.Items, matchesRequestedShape); ok {
		return match, nil
	}

	return ncsConfig{}, &cliError{
		Message: "created webhook config was not found in the API response.",
		Code:    "WEBHOOK_CONFIG_NOT_FOUND",
	}
}

func bestWebhookConfigCandidate(items []ncsConfig, matches func(ncsConfig) bool) (ncsConfig, bool) {
	var best ncsConfig
	found := false
	for _, item := range items {
		if !matches(item) {
			continue
		}
		if !found || item.UpdatedAt > best.UpdatedAt || (item.UpdatedAt == best.UpdatedAt && item.ConfigID > best.ConfigID) {
			best = item
			found = true
		}
	}
	return best, found
}

func (a *App) listWebhookEvents(feature string) ([]webhookEvent, error) {
	if err := validateWebhookFeature(feature); err != nil {
		return nil, err
	}
	var out ncsEventListResponse
	err := a.apiRequest("GET", "/api/cli/v1/ncs-events/"+feature, nil, nil, &out)
	if err != nil {
		return nil, err
	}
	return normalizeWebhookEvents(out), nil
}

func (a *App) listWebhookConfigs(projectID, feature string) (ncsConfigListResponse, error) {
	var out ncsConfigListResponse
	err := a.apiRequest("GET", "/api/cli/v1/projects/"+projectID+"/ncs-configs/"+feature, nil, nil, &out)
	return out, err
}

func (a *App) createWebhookConfig(projectID, feature string, body map[string]any) (ncsConfigListResponse, error) {
	var out ncsConfigListResponse
	err := a.apiRequest("POST", "/api/cli/v1/projects/"+projectID+"/ncs-configs/"+feature, nil, body, &out)
	return out, err
}

func (a *App) updateWebhookConfig(projectID, feature string, configID int, body map[string]any) (ncsConfigListResponse, error) {
	var out ncsConfigListResponse
	err := a.apiRequest("PUT", "/api/cli/v1/projects/"+projectID+"/ncs-configs/"+feature+"/"+strconv.Itoa(configID), nil, body, &out)
	return out, err
}

func (a *App) deleteWebhookConfig(projectID, feature string, configID int) error {
	out := map[string]any{}
	return a.apiRequest("DELETE", "/api/cli/v1/projects/"+projectID+"/ncs-configs/"+feature+"/"+strconv.Itoa(configID), nil, nil, &out)
}

func validateWebhookFeature(feature string) error {
	if strings.TrimSpace(feature) == "" {
		return &cliError{Message: "webhook feature is required", Code: "WEBHOOK_FEATURE_REQUIRED"}
	}
	return validateFeatureID(feature)
}

func normalizeWebhookDeliveryRegion(value string) (string, error) {
	region := strings.ToLower(strings.TrimSpace(value))
	switch region {
	case "cn", "sea", "na", "eu":
		return region, nil
	default:
		return "", &cliError{
			Message: fmt.Sprintf("invalid webhook delivery region %q. Choose one of: cn, sea, na, eu.", value),
			Code:    "WEBHOOK_DELIVERY_REGION_INVALID",
		}
	}
}

func defaultWebhookDeliveryRegion(controlPlaneRegion string) string {
	if strings.ToLower(strings.TrimSpace(controlPlaneRegion)) == "cn" {
		return "cn"
	}
	return "na"
}

func generateWebhookSecret() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validateWebhookSecret(secret string) error {
	if webhookSecretPattern.MatchString(secret) {
		return nil
	}
	return &cliError{
		Message: "webhook secret must be 7-32 URL-safe characters.",
		Code:    "WEBHOOK_SECRET_INVALID",
	}
}

func webhookIntSlicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func webhookIntSetEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := append([]int(nil), a...)
	sortedB := append([]int(nil), b...)
	sort.Ints(sortedA)
	sort.Ints(sortedB)
	return webhookIntSlicesEqual(sortedA, sortedB)
}

func resolveWebhookEventIDs(events []webhookEvent, inputs []string, feature string) ([]int, error) {
	byID := make(map[int]webhookEvent, len(events))
	byKey := make(map[string][]webhookEvent, len(events))
	byDisplayName := make(map[string][]webhookEvent, len(events))
	for _, event := range events {
		byID[event.ID] = event
		if event.Key != "" {
			byKey[event.Key] = append(byKey[event.Key], event)
		}
		byDisplayName[event.DisplayName] = append(byDisplayName[event.DisplayName], event)
	}

	selected := make(map[int]struct{}, len(inputs))
	for _, input := range inputs {
		value := strings.TrimSpace(input)
		if value == "" {
			continue
		}
		if id, err := strconv.Atoi(value); err == nil {
			if _, ok := byID[id]; !ok {
				return nil, unknownWebhookEventError(input, feature)
			}
			selected[id] = struct{}{}
			continue
		}
		if matches := byKey[value]; len(matches) > 0 {
			ids := uniqueWebhookEventIDs(matches)
			if len(ids) > 1 {
				return nil, &cliError{
					Message: fmt.Sprintf("webhook event %q is ambiguous. Use the numeric event ID instead.", input),
					Code:    "WEBHOOK_EVENT_AMBIGUOUS",
				}
			}
			selected[ids[0]] = struct{}{}
			continue
		}
		if matches := byDisplayName[value]; len(matches) > 0 {
			ids := uniqueWebhookEventIDs(matches)
			if len(ids) > 1 {
				return nil, &cliError{
					Message: fmt.Sprintf("webhook event %q is ambiguous. Use the numeric event ID instead.", input),
					Code:    "WEBHOOK_EVENT_AMBIGUOUS",
				}
			}
			selected[ids[0]] = struct{}{}
			continue
		}
		return nil, unknownWebhookEventError(input, feature)
	}

	out := make([]int, 0, len(selected))
	for id := range selected {
		out = append(out, id)
	}
	sort.Ints(out)
	return out, nil
}

func uniqueWebhookEventIDs(events []webhookEvent) []int {
	seen := make(map[int]struct{}, len(events))
	ids := make([]int, 0, len(events))
	for _, event := range events {
		if _, ok := seen[event.ID]; ok {
			continue
		}
		seen[event.ID] = struct{}{}
		ids = append(ids, event.ID)
	}
	return ids
}

func unknownWebhookEventError(input string, feature string) error {
	return &cliError{
		Message: fmt.Sprintf("unknown webhook event %q. Run `agora project webhook events --feature %s` to see available events.", input, strings.TrimSpace(feature)),
		Code:    "WEBHOOK_EVENT_UNKNOWN",
	}
}
