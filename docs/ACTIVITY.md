# Activity files (`.pka`) and the Activity Wizard

Reverse-engineered from PT 9.0.1.  A `.pka` activity is the **same encrypted
container** as a `.pkt` (see [FORMAT.md](../FORMAT.md)) whose plaintext XML root
is `<PACKETTRACER5_ACTIVITY>` instead of `<PACKETTRACER5>`.  Opening a `.pka`
puts Packet Tracer into *activity* mode: instructions window, **Check Results**
(assessment), timers, permissions.

Everything below can be authored with [`tools/activity.py`](../tools/activity.py).

## 1. Top-level layout

```xml
<PACKETTRACER5_ACTIVITY>
  <VERSION>9.0.1.0858</VERSION>
  <PACKETTRACER5> … </PACKETTRACER5>   <!-- [0] current/working network -->
  <PACKETTRACER5> … </PACKETTRACER5>   <!-- [1] initial network         -->
  <PACKETTRACER5> … </PACKETTRACER5>   <!-- [2] answer network          -->
  <COMPARISONS> … </COMPARISONS>       <!-- grading tree                -->
  <INITIALSETUP> … </INITIALSETUP>     <!-- scoring tree (item list)    -->
  <LOCKINGTREE enabled="no"> … </LOCKINGTREE>
  <OPTIONS> … </OPTIONS>
  <ACTIVITY …> … </ACTIVITY>           <!-- password, timer, instructions -->
  <VARIABLE_MANAGER> … </VARIABLE_MANAGER>
  <OVERALL_INCOMPLETE_FEEDBACK translate="true">…</OVERALL_INCOMPLETE_FEEDBACK>
  <OVERALL_COMPLETE_FEEDBACK   translate="true">…</OVERALL_COMPLETE_FEEDBACK>
  <UNLOCK_ASSESSMENT_ITEM_PERCENT>100</UNLOCK_ASSESSMENT_ITEM_PERCENT>
  <DYNAMIC_PERCENTAGE_FEEDBACK TYPE="0">false</DYNAMIC_PERCENTAGE_FEEDBACK>
  <USER_PROFILE_LOCKED>false</USER_PROFILE_LOCKED>
  <USER_PROFILE_NOGUEST>false</USER_PROFILE_NOGUEST>
  <COMPONENT_LIST>Other, Physical, Ip</COMPONENT_LIST>
  <CLEAN_ACTIVITY>false</CLEAN_ACTIVITY>
  <SCRIPT_MODULE> … </SCRIPT_MODULE>
  <AUTHOR>…</AUTHOR>
  <OBJECT_LOCATIONS INDEX=""> … </OBJECT_LOCATIONS>
  <START_TIMESTAMP>…</START_TIMESTAMP>
  <CEPS> … </CEPS>
  <EXT_PORT_MGR> … </EXT_PORT_MGR>
</PACKETTRACER5_ACTIVITY>
```

### The three embedded networks

Every activity embeds **three** complete `<PACKETTRACER5>` network documents:

| index | role | notes |
| --- | --- | --- |
| 0 | current / working | state the file opens in; PT saves it as it works |
| 1 | **initial** network | the "reset" starting point |
| 2 | **answer** network | the solution the assessment grades against |

Observed invariant in real files: blocks 0 and 1 are byte-identical on a fresh
save; block 2 holds the answer.  So to author: set **0 = 1 = initial**, and
**2 = answer**.  Each block is itself a normal network file — produce one with
[`pt9`](../pt9.py) / [`lab_api`](CAPABILITIES.md).

## 2. `<ACTIVITY>` — password, timer, instructions

```xml
<ACTIVITY FORWARD_ANS_SIM_MS="0" COUNTDOWNMS="10000" ELAPSED="5509"
          COUNTDOWN_EXPIRED="0" PASS="" TIMERTYPE="0" ENABLED="no"
          COUNTDOWNLEFT="10000">
  <INSTRUCTIONS enable_tab="false" layout="0">
    <PAGE translate="true" tabify="0" title=""><![CDATA[<html …>…</html>]]></PAGE>
  </INSTRUCTIONS>
  <INSTRUCTION_DIALOG>
    <USER_NOTES isDirty="false" tabify="0"><![CDATA[]]></USER_NOTES>
  </INSTRUCTION_DIALOG>
</ACTIVITY>
```

* **`PASS`** — the **Activity-Wizard password**.  Empty = none.
  (This is the authoring password, not a device/console password.)
* **`ENABLED`** `yes|no`, **`COUNTDOWNMS`**, **`TIMERTYPE`**, `COUNTDOWNLEFT`,
  `COUNTDOWN_EXPIRED`, `ELAPSED`, `FORWARD_ANS_SIM_MS` — the optional countdown.
* **`<INSTRUCTIONS>`** holds one or more `<PAGE>`s; each page body is **HTML in
  a CDATA block**.  `enable_tab` shows instructions in a dockable tab.
  Instructions may embed **`<script>`** calling the IPC API, e.g.
  `<script>ipc.appWindow().getActiveFile().getOptions().setHideDevModelLabel(true,true);</script>`.
* `<INSTRUCTION_DIALOG>/<USER_NOTES>` is the student's note scratch-pad.

## 3. Scoring / assessment

`<INITIALSETUP>` (item list shown in Check Results) and `<COMPARISONS>` (what the
grader compares) are **parallel trees of `<NODE>`s**:

```xml
<NODE>
  <NAME checkType="0" eclass="8" headNode="true" incorrectFeedback=""
        nodeValue="" obfuscateName="false" overrideDBGrading="false"
        variableEnabled="false" variableName="">Network</NAME>
  <ID>Network</ID>
  <COMPONENTS></COMPONENTS>   <!-- which component categories this item covers -->
  <POINTS></POINTS>           <!-- points awarded for this item -->
  <NODE> … child items … </NODE>
</NODE>
```

Useful `NAME` attributes:

* `checkType` — grading mode (0 = compare, 1 = custom/scripted, …).
* `eclass` — item class (8 = container/network node).
* `headNode` — has children.
* `nodeValue` — expected value (empty = arbitrary).
* `incorrectFeedback` — message when the item fails.
* `overrideDBGrading` — grade from the answer network even if the item is locked.
* `variableName` / `variableEnabled` — bind the item to a variable pool.

`<COMPONENT_LIST>` selects which categories are graded; observed categories:
`Ip, Other, Routing, Acl, Switching, Physical, Nat`.  `<UNLOCK_ASSESSMENT_ITEM_PERCENT>`
is the score at which later items unlock; `<DYNAMIC_PERCENTAGE_FEEDBACK TYPE>`
toggles dynamic feedback.

Per-subsystem custom graders exist in the binary
(`<Process>::doCustomGrading(Activity::CActivityItemTreeNode*)` for Aaa, Acl,
Ospf, Dhcp, …) and are selected by `checkType`.

### Generating scoring offline (important)

Packet Tracer **validates the scoring tree against the network's item model**.
A hand-built minimal node is rejected — the activity then fails to open with a
misleading *"requires version …"* error — while a **complete** device node cloned
from a real activity loads fine.  So scoring is authored by **cloning complete
item nodes from a reference activity** and retargeting them:

```python
import scoring, activity
ref = pt9.decode("reference_activity.pkt").decode()          # has 2911/PC-PT nodes
vals = scoring.derive_values(pt9.decode("answer.pkt"))       # {device: {item: value}}
init, comp = scoring.from_template(
    ref,
    devices=["ISP-Router", "DMZ-Switch", "Branch-Admin-PC"], # reference nodes to clone
    rename={"ISP-Router": "R9", "DMZ-Switch": "SW9", "Branch-Admin-PC": "PC9"},
    overrides=vals)                                          # expected values per device
activity.Activity("reference.pkt") \
    .set_instructions(["<h3>Task</h3>…"]) \
    .set_password("…") \
    .set_scoring_xml(init, comp) \
    .set_networks(initial_xml=start, answer_xml=done) \
    .save("mylab.pka")
```

* Pick a reference activity whose tree already contains device nodes of the
  classes you need (a router activity for routers, …).  `ApexDefense`-style
  competition activities are rich sources (2911, 2960, 3560, PC-PT, Server-PT…).
* `scoring.derive_values(answer)` reads interface IPs/masks, `no shutdown`, device
  model and end-device gateway from the answer network and feeds them in as the
  expected `nodeValue`s.
* The renamed devices must **exist in the answer network**; the tree resolves
  items by device name.

**Verified**: a custom activity built this way (instructions, password,
permissions, our own network, cloned+retargeted scoring) opens in Packet Tracer
with the instructions window, **Check Results**, and a computed **Completion**.

## 4. Permissions / locking

* **`<USER_PROFILE_LOCKED>`** `true|false` — require a named user profile (shows
  the Name/E-mail dialog on open).
* **`<USER_PROFILE_NOGUEST>`** `true|false` — disallow the Guest profile.
* **`<COMPONENT_LIST>`** — graded categories (see above).
* **`<LOCKINGTREE enabled="yes|no">`** — node tree of lockable UI/feature items;
  each `<NODE on="yes|no"><ID>…</ID><TEXT>…</TEXT>…</NODE>`.  Present keys
  include `Interface`, `Switching to Logical/Physical Workspace`,
  `Switching to Realtime/Simulation Mode`, and per-operation locks.  `on="yes"`
  **locks** (denies) that item for the student.

## 5. Feedback, variables, scripts, metadata

* `<OVERALL_INCOMPLETE_FEEDBACK>` / `<OVERALL_COMPLETE_FEEDBACK>` — messages
  shown after Check Results.
* `<VARIABLE_MANAGER>` — `<SEED_POOLS/>`, `<NUMBER_POOLS/>`, `<STRING_POOLS/>`,
  `<IP_POOLS/>`, `<VARIABLES_POOLS/>` for randomized variants.
* `<SCRIPT_MODULE>` — mirrors a network file's script module (embedded activity
  scripts, `PT_APP_META`).
* `<AUTHOR>`, `<START_TIMESTAMP>`, `<OBJECT_LOCATIONS>`, `<CEPS>`,
  `<EXT_PORT_MGR>` — author/time bookkeeping, per-object locations, IPC/port mgr.

## 6. Authoring

```python
from activity import Activity
a = Activity("template.pka")                       # any real activity as a base
a.set_instructions(["<h3>Task</h3><p>Configure R1…</p>"])
a.set_password("hunter2")                          # Activity-Wizard password
a.set_timer(enabled=True, seconds=600)             # optional countdown
a.set_permissions(locked=True, noguest=True,
                  component_list="Ip, Routing, Switching, Physical",
                  locking_enabled=True)
a.set_feedback(incomplete="Not done yet!", complete="Great job!")
a.set_unlock_percent(80)
a.set_networks(initial_xml=open("start.xml","rb").read(),   # <PACKETTRACER5>…
               answer_xml =open("done.xml","rb").read())
a.save("mylab.pka")
```

Building `start.xml` / `done.xml`: decode or generate networks with
`pt9` / `lab_api` (place devices, install modules, cable, write configs), then
`pt9.decode(pkt)` to get the `<PACKETTRACER5>…</PACKETTRACER5>` text.

**Verified**: a generated `.pka` (custom instructions, password, permissions,
replaced networks) opens in Packet Tracer showing the instructions window, the
**Check Results** button, the timer, and the permission-gated login dialog.

## 7. Editing an existing activity in place

Because the container is byte-exact, you can also decode any `.pka`, tweak a
subtree (e.g. a single `<POINTS>` value or an `<incorrectFeedback>`), and
re-encode — no Packet Tracer needed.  The shipped **shape library** (`tools/device_shapes.json`, 14 models) lets
`scoring.from_shapes(spec, shapes)` build trees for any covered model directly;
models without a shape are skipped (not graded) rather than failing.  Extend it
with `tools/harvest_library.py`.  `tools/activity.py` exposes helpers for the
common fields; anything else is a direct string/XML edit of the decoded text.
