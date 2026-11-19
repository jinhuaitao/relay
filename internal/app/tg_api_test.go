package app

import (
	"strings"
	"testing"
)

func TestTgChunksShort(t *testing.T) {
	got := tgChunks("hello", 4000)
	if len(got) != 1 || got[0] != "hello" {
		t.Errorf("short text must pass through, got %v", got)
	}
}

func TestTgChunksRoundTrip(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		sb.WriteString(strings.Repeat("流量统计x", 20))
		sb.WriteByte('\n')
	}
	text := sb.String()
	chunks := tgChunks(text, 4000)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	if strings.Join(chunks, "") != text {
		t.Error("concatenated chunks must equal original text")
	}
	for i, ch := range chunks {
		if len([]rune(ch)) > 4000 {
			t.Errorf("chunk %d exceeds limit: %d runes", i, len([]rune(ch)))
		}
		if i < len(chunks)-1 && !strings.HasSuffix(ch, "\n") {
			t.Errorf("chunk %d should break at newline", i)
		}
	}
}

func TestTgChunksNoNewline(t *testing.T) {
	text := strings.Repeat("a", 9000)
	chunks := tgChunks(text, 4000)
	if strings.Join(chunks, "") != text {
		t.Error("round trip failed without newlines")
	}
	for _, ch := range chunks {
		if len([]rune(ch)) > 4000 {
			t.Error("chunk exceeds limit")
		}
	}
}

func TestMakeAestheticBar(t *testing.T) {
	if got := makeAestheticBar(0, "━", "─"); got != strings.Repeat("─", 12) {
		t.Errorf("0%%: %q", got)
	}
	if got := makeAestheticBar(1, "━", "─"); !strings.HasPrefix(got, "━") {
		t.Errorf("1%% must light at least one block: %q", got)
	}
	if got := makeAestheticBar(100, "━", "─"); got != strings.Repeat("━", 12) {
		t.Errorf("100%%: %q", got)
	}
	if got := makeAestheticBar(150, "━", "─"); got != strings.Repeat("━", 12) {
		t.Errorf("over-range must clamp: %q", got)
	}
	if got := makeAestheticBar(-5, "━", "─"); got != strings.Repeat("─", 12) {
		t.Errorf("negative must clamp: %q", got)
	}
}

func TestTgEscape(t *testing.T) {
	if got := tgEscape("<b>&"); got != "&lt;b&gt;&amp;" {
		t.Errorf("tgEscape: %q", got)
	}
}