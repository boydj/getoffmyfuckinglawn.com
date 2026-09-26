package logstore

// Event is the minimal view of one request needed to derive sessions. Events
// for a single (ip, user_agent) must be passed sorted by TsStart.
type Event struct {
	TsStart     int64 // unix ms
	TsEnd       int64 // unix ms; 0 or < TsStart means "same as TsStart"
	IsViolation bool  // /lawn/* hit
	IsRobots    bool  // /robots.txt fetch
	Depth       int
	Bytes       int64
}

// Session is a derived run of consecutive requests from one (ip, user_agent).
type Session struct {
	Start      int64 // first request start, unix ms
	End        int64 // latest request end, unix ms
	Requests   int
	Pages      int   // violation requests
	HeldMs     int64 // sum of (ts_end - ts_start) over violations
	Bytes      int64 // bytes sent on violations
	MaxDepth   int
	FirstLawn  int64 // ts_start of first violation, 0 if none
	ReadRules  bool  // robots.txt fetched before FirstLawn in this session
	sawRobots  bool
	lastActive int64
}

// HeldMs returns the time held for one request (SPEC.md section 6).
func HeldMs(tsStart, tsEnd int64) int64 {
	if tsEnd <= tsStart {
		return 0
	}
	return tsEnd - tsStart
}

// DeriveSessions splits events (sorted by TsStart, all from one ip+ua) into
// sessions. A new session starts when the gap between an event's start and
// the latest end seen so far in the current session is >= gapMs. Measuring
// from the latest end (not the previous start) keeps a crawler that is held
// for longer than the gap by the drip in one session.
func DeriveSessions(events []Event, gapMs int64) []Session {
	var out []Session
	var cur *Session
	for _, e := range events {
		end := e.TsEnd
		if end < e.TsStart {
			end = e.TsStart
		}
		if cur == nil || e.TsStart-cur.lastActive >= gapMs {
			out = append(out, Session{Start: e.TsStart, End: end, lastActive: end})
			cur = &out[len(out)-1]
		}
		cur.Requests++
		if end > cur.End {
			cur.End = end
		}
		if end > cur.lastActive {
			cur.lastActive = end
		}
		if e.IsRobots {
			cur.sawRobots = true
		}
		if e.IsViolation {
			if cur.FirstLawn == 0 {
				cur.FirstLawn = e.TsStart
				cur.ReadRules = cur.sawRobots
			}
			cur.Pages++
			cur.HeldMs += HeldMs(e.TsStart, e.TsEnd)
			cur.Bytes += e.Bytes
			if e.Depth > cur.MaxDepth {
				cur.MaxDepth = e.Depth
			}
		}
	}
	return out
}
