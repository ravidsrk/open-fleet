CATEGORY: bug
SUMMARY: Ancestor walk in spawn identity resolution fails closed to read-only cap under Linux hidepid=invisible whenever a live worker root exists beneath a hidden supervisor ancestor.

CURRENT BEHAVIOUR:
On Linux hosts where procfs is mounted with hidepid=invisible (or hidepid=2), non-root processes cannot stat ancestor processes owned by another user (such as a container supervisor) or non-dumpable intermediate processes. When the spawn registry has no live worker roots, whoami resolves the caller's process ancestry with hidden-ancestor tolerance enabled, so the walk stops cleanly at the hidden supervisor boundary. Once any parent worker registers a live root in the spawn registry, whoami disables hidden-ancestor tolerance unconditionally. When a child worker then runs whoami, the ancestry walk traverses the child and its visible parent worker root, reaches the hidden supervisor ancestor above the parent root, and raises Unknown ("ancestor <ppid> of <child> cannot be read"). The spawn wrapper treats that Unknown as unreadable spawn identity and caps the child at ro instead of preserving the parent's rw profile, causing monotonic-narrowing parent-profile checks to fail with spurious ro caps.

DESIRED BEHAVIOUR:
1. When procfs hides a shared supervisor ancestor P above every active worker root and host across both the active spawn registry and the UID-home fallback registry, whoami MUST resolve the caller's visible ancestry cleanly up to P and emit the true parent ROOT profile (for example rw) and INTREE status instead of raising Unknown.
2. Fail-closed W4-04 privilege-narrowing protection MUST remain strictly intact against EVERY evasion vector, including transitive hidden-intermediate evasion:
   - Stopping a caller's ancestry walk at an invisible ancestor P (where stat(P) returns None while the topmost visible child's stat still names P as its parent) is permitted ONLY when ALL of the following hold simultaneously:
     a. Both the active registry and the UID-home fallback registry (when distinct and present) have been consulted for live roots and live hosts BEFORE authorizing the hidden-boundary stop (preserving the HOME-switch defense).
     b. Every live root across both registries and every live host across both registries is currently visible and alive (alive(key) is True, never None/unreadable).
     c. The upward ancestry walk of EVERY live root and EVERY live host across both registries terminates at the EXACT SAME live hidden parent PID P (re-verified via stat on each topmost visible ancestor still naming P). Because the process tree is acyclic and P is an active parent of each root's and host's topmost visible ancestor, no live root or live host can sit above P.
3. Whenever ANY live root or live host is unreadable (alive(key) is None, e.g., stat raises Unknown / PermissionError), OR whenever any live root or live host terminates at a different parent than P (for example PID 1 or a different hidden supervisor, as happens when a visible ro root spawns a non-dumpable or setuid hidden intermediate process S that execs caller C), whoami MUST still raise Unknown so the spawn wrapper fails closed to ro.
4. PID-namespace ownership verification (own_proc) and HOME-switch registry folding MUST remain unchanged and strictly enforced.

KEY INTERFACES:
- whoami(reg: Registry, pid: int) -> list[str]: evaluates live roots and live hosts across both reg and the UID-home Registry before deciding whether an invisible ancestor P is a provably shared boundary above every live root and host; emits unchanged line grammar (ROOT, INTREE, ANCHORED, LIVE, RESERVATION, SELF) or raises Unknown.
- chain(pid: int, *, allow_hidden: bool = False) -> list[str] (or a companion helper returning both the visible key chain and any hidden stopping parent PID): returns the visible ancestry keys and identifies the exact invisible parent PID P (re-verified against child's current parent PID so reparenting races still loop rather than falsely stopping).
- alive(key: str) -> bool | None and stat(pid: int) -> tuple[int, str] | None: preserve existing three-state semantics (None from stat means process is gone / alive returns False; Unknown raised from stat means unreadable / alive returns None).

ACCEPTANCE CRITERIA:
- [ ] Single-variable live reproduction passes: running the spawn-worker monotonic parent-profile narrowing test inside a hidepid=invisible Linux environment beneath a hidden supervisor ancestor (whether a root-owned container supervisor or a non-dumpable supervisor process above the coordinator and worker) succeeds and reports the parent's actual rw profile rather than falling back to an Unknown ro cap.
- [ ] Unit test for shared hidden supervisor: with child PID 300 -> visible rw root PID 200 (and live host) -> hidden supervisor PID 100 (stat(100) returns None), whoami(reg, 300) returns ROOT rw for PID 200 and does NOT raise Unknown.
- [ ] Fail-closed negative control 1 (unreadable live root): when any live root in the active or UID-home registry has stat(other_root) raising Unknown (so alive(other_root) is None, NOT stat returning None which prunes dead entries), whoami(reg, 300) raises Unknown.
- [ ] Fail-closed negative control 2 (transitive hidden-intermediate W4-04 bypass): when a visible ro root PID 200 (whose walk ends at PID 1 or supervisor PID 100) sits above a hidden intermediate process S PID 250 (stat(250) returns None, modelling PR_SET_DUMPABLE=0 or a setuid helper) which spawns caller PID 300 (ppid=250), whoami(reg, 300) MUST raise Unknown (never emit INTREE no / empty ROOT / exit 0) because caller stops at 250 != root's boundary.
- [ ] Fail-closed negative control 3 (HOME-switch + hidden intermediate): with HOME pointed at an empty temp registry while the UID-home registry holds a visible ro root above a hidden intermediate process S, whoami MUST still consult UID-home roots/hosts before permitting a hidden-boundary stop and MUST raise Unknown.
- [ ] Fail-closed negative control 4 (hidden intermediate below live host): when a visible live host sits above a hidden intermediate process S that spawns caller C, whoami MUST raise Unknown rather than flipping INTREE from yes to no.
- [ ] Full spawn-worker test suite passes on both standard procfs/macOS hosts and Linux hidepid=invisible hosts, and the fix unit executes under lit lighting with independent security review.

OUT OF SCOPE:
- Changing host Linux kernel or container procfs mount flags (hidepid=invisible is an external host security policy).
- Weakening or altering the spawn wrapper's fail-closed ro capping behavior when spawn identity exits non-zero.
- Modifying own_proc PID-namespace checks or weakening non-dumpable process scanning during root recording.
- Landing any production or test code changes as part of this diagnosis run (fix authority belongs to a separately authorized mission).
