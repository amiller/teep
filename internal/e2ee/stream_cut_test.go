package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type streamCut struct{}

func (streamCut) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

const cutChunks = "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n"

// checkStreamEnding asserts that a stream cut before its end marker ends with
// an upstream_error event and no [DONE], and that a complete one ends with
// [DONE] and no error event.
func checkStreamEnding(t *testing.T, body string, err error, cut bool) {
	t.Helper()
	hasError := strings.Contains(body, "event: error\ndata: ")
	hasDone := strings.Contains(body, "data: [DONE]")
	if !cut {
		if err != nil || hasError || !hasDone {
			t.Fatalf("complete stream: err=%v error_event=%v done=%v\n%s", err, hasError, hasDone, body)
		}
		return
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrRelayFailed) {
		t.Fatalf("cut stream lost its error: %v", err)
	}
	if hasDone || !hasError {
		t.Fatalf("cut stream: error_event=%v done=%v\n%s", hasError, hasDone, body)
	}
	data, _ := strings.CutPrefix(strings.TrimSpace(body[strings.LastIndex(body, "data: "):]), "data: ")
	var event struct {
		Error struct{ Message, Type string }
	}
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		t.Fatalf("error event is not JSON: %v: %s", err, data)
	}
	if event.Error.Type != "upstream_error" || event.Error.Message != "upstream stream ended early: unexpected EOF" {
		t.Fatalf("error event = %+v", event.Error)
	}
}

func TestRelayStreamUpstreamCut(t *testing.T) {
	for _, cut := range []bool{false, true} {
		t.Run(fmt.Sprintf("cut=%v", cut), func(t *testing.T) {
			var body io.Reader = strings.NewReader(cutChunks + "data: [DONE]\n\n")
			if cut {
				body = io.MultiReader(strings.NewReader(cutChunks), streamCut{})
			}
			rec := httptest.NewRecorder()
			stats, err := RelayStream(context.Background(), rec, body, nil, EndpointChat)
			if stats.Forwarded == 0 {
				t.Fatal("no chunks forwarded")
			}
			checkStreamEnding(t, rec.Body.String(), err, cut)
		})
	}
}

func TestRelayStreamChutesUpstreamCut(t *testing.T) {
	for _, cut := range []bool{false, true} {
		t.Run(fmt.Sprintf("cut=%v", cut), func(t *testing.T) {
			session, err := NewChutesSession()
			if err != nil {
				t.Fatal(err)
			}
			kemCtB64, streamKey := simulateServerStreamInit(t, session)
			sse := buildChutesSSE(t, kemCtB64, streamKey, []string{"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n"})
			var body io.Reader = strings.NewReader(sse)
			if cut {
				body = io.MultiReader(strings.NewReader(strings.TrimSuffix(sse, "data: [DONE]\n\n")), streamCut{})
			}
			rec := httptest.NewRecorder()
			_, err = RelayStreamChutes(context.Background(), rec, body, session)
			checkStreamEnding(t, rec.Body.String(), err, cut)
		})
	}
}

// A Chutes stream cut before any content writes nothing, so the caller can
// still retry another instance.
func TestRelayStreamChutesCutBeforeHeaders(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatal(err)
	}
	kemCtB64, _ := simulateServerStreamInit(t, session)
	initJSON, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	rec := httptest.NewRecorder()
	_, err = RelayStreamChutes(context.Background(), rec, io.MultiReader(strings.NewReader("data: "+string(initJSON)+"\n\n"), streamCut{}), session)
	if !errors.Is(err, io.ErrUnexpectedEOF) || rec.Body.Len() != 0 {
		t.Fatalf("err=%v body=%q", err, rec.Body.String())
	}
}
