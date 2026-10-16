"""Activity builder: author scored Packet Tracer activity files (.pka).

Author instructions, activity password, timed assessments, feedback,
and initial versus answer networks without Packet Tracer.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from pkt_core.builder import scoring
from pkt_core.codec import decode_bytes, encode
from pkt_core.errors import ActivityError
from pkt_core.resources import load_bundled_activity_skeleton

__all__ = ["Activity"]

PKT = re.compile(r"<PACKETTRACER5>.*?</PACKETTRACER5>", re.S)


class Activity:
    """Author Packet Tracer *activity* files (.pka) programmatically.

    The .pka container root is ``<PACKETTRACER5_ACTIVITY>`` and embeds
    three ``<PACKETTRACER5>`` documents:
    - [0]: working / current network
    - [1]: initial network (unconfigured)
    - [2]: answer network (graded target)

    Example::

        from pkt_core import Activity, Lab

        act = Activity()  # Uses bundled skeleton
        act.set_instructions("<h3>Task</h3><p>Configure R1...</p>")
        act.set_password("cisco123")
        act.save("my_lab.pka")
    """

    def __init__(self, template: str | Path | bytes | None = None) -> None:
        """Initialize an Activity.

        Args:
            template: Path to a template .pka/.pkt file, raw XML bytes, or None
                to use the bundled activity skeleton.
        """
        if template is None:
            self.xml = load_bundled_activity_skeleton()
        elif isinstance(template, (str, Path)):
            path = Path(template)
            raw = path.read_bytes()
            if path.suffix.lower() in (".pka", ".pkt"):
                raw = decode_bytes(raw, "pkt").xml
            self.xml = raw.decode("utf-8")
        elif isinstance(template, bytes):
            if template.startswith(b"<"):
                self.xml = template.decode("utf-8")
            else:
                self.xml = decode_bytes(template, "pkt").xml.decode("utf-8")
        else:
            raise TypeError(
                f"template must be a path, bytes, or None; got {type(template)}"
            )

        if "<PACKETTRACER5_ACTIVITY>" not in self.xml:
            raise ActivityError(
                "Template is not an activity (missing <PACKETTRACER5_ACTIVITY>)"
            )
        if len(PKT.findall(self.xml)) < 3:
            raise ActivityError(
                "Activity template does not embed 3 networks (working, initial, answer)"
            )

    # ---- rewriting helpers -------------------------------------------------
    def _set_attr(self, tag: str, name: str, value: str) -> None:
        m = re.search(rf"<{tag}\b[^>]*>", self.xml)
        if not m:
            return
        el = m.group(0)
        if re.search(rf'\b{name}="[^"]*"', el):
            el = re.sub(rf'\b{name}="[^"]*"', f'{name}="{value}"', el)
        else:
            el = el[:-1] + f' {name}="{value}">'
        self.xml = self.xml[: m.start()] + el + self.xml[m.end() :]

    def _set_text(self, tag: str, value: str) -> None:
        self.xml = re.sub(
            rf"<{tag}(?:\s[^>]*)?>.*?</{tag}>",
            f"<{tag}>{value}</{tag}>",
            self.xml,
            count=1,
            flags=re.S,
        )

    # ---- public API --------------------------------------------------------
    def set_instructions(
        self,
        pages: str | Sequence[str],
        enable_tab: bool = False,
        layout: int = 0,
        title: str = "",
    ) -> None:
        """Set activity instructions (HTML string or list of HTML page strings)."""
        if isinstance(pages, str):
            page_list = [pages]
        else:
            page_list = list(pages)
        body = "".join(
            f'<PAGE translate="true" tabify="{i}" title="{title}"><![CDATA[{html}]]></PAGE>'
            for i, html in enumerate(page_list)
        )
        tab_str = "true" if enable_tab else "false"
        new = f'<INSTRUCTIONS enable_tab="{tab_str}" layout="{layout}">{body}</INSTRUCTIONS>'
        self.xml = re.sub(
            r"<INSTRUCTIONS\b[^>]*>.*?</INSTRUCTIONS>",
            new,
            self.xml,
            count=1,
            flags=re.S,
        )

    def set_password(self, password: str) -> None:
        """Set the Activity-Wizard password (ACTIVITY/@PASS)."""
        self._set_attr("ACTIVITY", "PASS", password)

    def set_timer(self, enabled: bool = True, seconds: int = 0) -> None:
        """Configure assessment countdown timer."""
        self._set_attr("ACTIVITY", "ENABLED", "yes" if enabled else "no")
        self._set_attr("ACTIVITY", "TIMERTYPE", "1" if seconds else "0")
        self._set_attr("ACTIVITY", "COUNTDOWNMS", str(int(seconds) * 1000))

    def set_permissions(
        self,
        locked: bool | None = None,
        noguest: bool | None = None,
        component_list: str | None = None,
        locking_enabled: bool | None = None,
    ) -> None:
        """Configure user profile and interface locking."""
        if locked is not None:
            self._set_text(
                "USER_PROFILE_LOCKED", "true" if locked else "false"
            )
        if noguest is not None:
            self._set_text(
                "USER_PROFILE_NOGUEST", "true" if noguest else "false"
            )
        if component_list is not None:
            self._set_text("COMPONENT_LIST", component_list)
        if locking_enabled is not None:
            self._set_attr(
                "LOCKINGTREE", "enabled", "yes" if locking_enabled else "no"
            )

    def set_feedback(
        self, incomplete: str | None = None, complete: str | None = None
    ) -> None:
        """Set completion and incompletion feedback text."""
        if incomplete is not None:
            self._set_text("OVERALL_INCOMPLETE_FEEDBACK", incomplete)
        if complete is not None:
            self._set_text("OVERALL_COMPLETE_FEEDBACK", complete)

    def set_unlock_percent(self, percent: int | float) -> None:
        """Set threshold percentage required to unlock assessment items."""
        self._set_text("UNLOCK_ASSESSMENT_ITEM_PERCENT", str(int(percent)))

    def set_clean_activity(self, flag: bool) -> None:
        self._set_text("CLEAN_ACTIVITY", "true" if flag else "false")

    def set_scoring_xml(
        self, initialsetup_xml: str, comparisons_xml: str
    ) -> None:
        """Inject raw <INITIALSETUP> and <COMPARISONS> XML trees."""
        self.xml = re.sub(
            r"<INITIALSETUP>.*?</INITIALSETUP>",
            initialsetup_xml,
            self.xml,
            count=1,
            flags=re.S,
        )
        self.xml = re.sub(
            r"<COMPARISONS>.*?</COMPARISONS>",
            comparisons_xml,
            self.xml,
            count=1,
            flags=re.S,
        )

    def set_scoring(
        self,
        spec: list[dict[str, Any]] | str | bytes,
        shapes: dict[str, Any] | None = None,
    ) -> None:
        """Set scoring tree from a spec or answer network."""
        if isinstance(spec, (str, bytes)):
            vals = scoring.derive_values(spec)
            spec_list = [{"name": k, "overrides": v} for k, v in vals.items()]
        else:
            spec_list = spec
        if shapes is None:
            from pkt_core.resources import load_bundled_device_shapes

            shapes = load_bundled_device_shapes()
        init, comp = scoring.from_shapes(spec_list, shapes)
        self.set_scoring_xml(init, comp)

    def set_networks(
        self,
        initial_xml: str | bytes | None = None,
        answer_xml: str | bytes | None = None,
    ) -> None:
        """Replace the initial (block 1) and answer (block 2) networks."""
        blocks = list(PKT.finditer(self.xml))
        if initial_xml is not None:
            init_str = (
                initial_xml.decode("utf-8")
                if isinstance(initial_xml, bytes)
                else initial_xml
            )
            for idx in (1, 0):
                b = blocks[idx]
                self.xml = (
                    self.xml[: b.start()] + init_str + self.xml[b.end() :]
                )
                blocks = list(PKT.finditer(self.xml))
        if answer_xml is not None:
            ans_str = (
                answer_xml.decode("utf-8")
                if isinstance(answer_xml, bytes)
                else answer_xml
            )
            b = blocks[2]
            self.xml = self.xml[: b.start()] + ans_str + self.xml[b.end() :]

    def to_xml(self) -> bytes:
        """Return the raw XML document bytes."""
        return self.xml.encode("utf-8")

    def save(self, path: str | Path, fmt: str = "pkt") -> None:
        """Encode and save the activity to a .pka container file."""
        encode(path, self.to_xml(), fmt=fmt)  # type: ignore[arg-type]

    export = save  # Convenient alias

