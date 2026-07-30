#!/usr/bin/env python3
"""Bitcoin app playground — Textual TUI front-end.

Mirrors the CLI subcommands as tabs, but adds *presets* on top: a preset
prefills the form fields of one tab. Presets that include device-derived
keys are resolved eagerly against the connected device — picking
`tr-singlesig`, for example, immediately calls get_xpub at m/86'/1'/0' and
populates the keys textarea with the resulting `[fpr/path]xpub`. The
user can still edit any field afterward.

Each Run button builds an `argparse.Namespace` matching the corresponding
`cmd_*` function in `cli.py` (which is now preset-free and takes a fully
inline wallet policy) and dispatches it on a worker thread with
stdout/stderr captured into the Output panel.

Run from the repo root, with the project venv active:

    python dev-tools/playground/gui.py

Speculos is expected to be running separately (default 127.0.0.1:9999).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import threading
import traceback
from pathlib import Path
from typing import Any, Callable, List, Optional

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for p in (_REPO_ROOT, _HERE):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from textual import events, on, work  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402
from textual.containers import Horizontal, VerticalScroll  # noqa: E402
from textual.widgets import (  # noqa: E402
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from cli import (  # noqa: E402
    CHAIN_BY_NAME,
    cmd_get_address,
    cmd_get_fingerprint,
    cmd_get_xpub,
    cmd_register_wallet,
    cmd_sign_message,
    cmd_sign_psbt,
)
from presets import (  # noqa: E402
    POLICY_PRESETS,
    PolicyPreset,
    XPUB_PRESETS,
    XpubPreset,
    external_key_info,
    external_xpriv,
    sign_psbt_presets,
)


NO_PRESET = ""                     # sentinel value used by every Preset Select
PSBT_BASE64_PREFIX = "cHNidP"      # base64-encoded "psbt"


def _preset_choices(presets) -> list[tuple[str, str]]:
    """Build the `(label, value)` list for a preset combobox.

    The first entry is a "(no preset)" sentinel that doesn't prefill anything;
    the rest show `name — description` so the user knows what each one does.
    """
    out: list[tuple[str, str]] = [("(no preset)", NO_PRESET)]
    for p in presets:
        out.append((f"{p.name} — {p.description}", p.name))
    return out


# ----- connection probing ----------------------------------------------------

def _try_target(target: str, host: str, port: int, chain) -> Optional[str]:
    """Attempt a transport connection plus a `get_version()` round-trip.

    Returns `None` on success (Bitcoin (Test) app open and reachable), or a
    short human-readable error string on failure.
    """
    from bitcoin_client.ledger_bitcoin import TransportClient, createClient

    try:
        if target == "speculos":
            transport = TransportClient(interface="tcp", server=host, port=port)
        elif target == "hid":
            transport = TransportClient(interface="hid")
        else:
            return f"unknown target {target!r}"
    except ConnectionRefusedError:
        return f"speculos not running at {host}:{port}"
    except OSError as e:
        if target == "speculos":
            return f"speculos unreachable at {host}:{port} ({e})"
        return f"no Ledger USB device detected ({e})"
    except Exception as e:  # broad on purpose — hidapi raises varied types
        if target == "hid":
            return f"no Ledger USB device detected ({type(e).__name__}: {e})"
        return f"transport setup failed ({type(e).__name__}: {e})"

    client = None
    try:
        client = createClient(transport, chain=chain)
        app_name, _version, _flags = client.get_version()
    except Exception as e:
        return f"could not read app version ({type(e).__name__}: {e})"
    finally:
        if client is not None:
            try:
                client.stop()
            except Exception:
                pass

    if not app_name.startswith("Bitcoin"):
        return (
            f"the Bitcoin (Test) app is not open on the device "
            f"(saw {app_name!r})"
        )
    return None


# ----- clipboard read (for right-click paste) --------------------------------

def _read_clipboard() -> Optional[str]:
    """Read text from the OS clipboard.

    Textual captures mouse events, so the terminal's own right-click-paste
    never reaches the cursor. We re-implement it by shelling out to a
    standard clipboard tool: xclip / xsel / wl-paste / pbpaste, returning
    the first one that succeeds. Returns None if none are available or the
    clipboard is empty.
    """
    import subprocess
    candidates = [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste", "--no-newline"],
        ["pbpaste"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout:
            return result.stdout
    return None


# ----- stdout/stderr capture -------------------------------------------------

class _LogStream:
    """Captures writes from a worker thread and forwards them to a RichLog."""

    def __init__(self, app: App, log: RichLog, is_err: bool) -> None:
        self._app = app
        self._log = log
        self._is_err = is_err
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, s: str) -> int:
        with self._lock:
            self._buf += s
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                self._emit(line)
        return len(s)

    def flush(self) -> None:
        with self._lock:
            if self._buf:
                self._emit(self._buf)
                self._buf = ""

    def _emit(self, line: str) -> None:
        text = f"[dim]{line}[/]" if self._is_err else line
        self._app.call_from_thread(self._log.write, text)

    def isatty(self) -> bool:
        return False


# ----- the app ---------------------------------------------------------------

class PlaygroundApp(App):
    """Textual front-end for the Bitcoin app playground."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #status_bar {
        height: 1;
        padding: 0 2;
        background: $boost;
        color: $text-muted;
    }
    TabbedContent {
        height: 3fr;
        min-height: 12;
    }
    TabPane {
        layout: vertical;
        padding: 0;
    }
    /* Scrollable region holding a tab's inputs. The Run bar below it is
       pinned, so the button stays visible even when the form overflows. */
    .tab-body {
        height: 1fr;
        padding: 1 2 0 2;
    }
    .form-row {
        height: 3;
    }
    .form-row Label {
        width: 22;
        content-align: left middle;
    }
    .form-row Input {
        width: 1fr;
    }
    /* Preset dropdowns. Without this, a long `name — description` label wraps
       onto several lines, which pushes most of the preset names out of the
       overlay; one line per preset keeps every name in view. */
    Select > SelectOverlay {
        max-height: 20;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    .keys-area {
        height: 6;
    }
    .actions {
        height: auto;
        align-horizontal: right;
        padding: 0 2;
        border-top: solid $panel;
    }
    .actions Button {
        margin-left: 2;
    }
    #log {
        height: 1fr;
        min-height: 6;
        max-height: 16;
        border: round $primary;
        padding: 0 1;
    }
    #sign_psbt_input {
        height: 5;
    }
    """

    BINDINGS = [
        ("ctrl+l", "clear_log", "Clear log"),
        ("ctrl+r", "reconnect", "Reconnect"),
        ("ctrl+q", "quit", "Quit"),
    ]

    # Presets shown on each policy tab.
    REGISTER_PRESETS = [p for p in POLICY_PRESETS if p.needs_registration]
    ADDR_PRESETS = list(POLICY_PRESETS)
    SIGN_PRESETS = sign_psbt_presets()

    def __init__(
        self,
        target: str = "auto",
        host: str = "127.0.0.1",
        port: int = 9999,
        chain: str = "test",
        debug: bool = False,
    ) -> None:
        super().__init__()
        if target not in ("auto", "speculos", "hid"):
            raise ValueError(f"invalid target: {target!r}")
        if chain not in CHAIN_BY_NAME:
            raise ValueError(f"invalid chain: {chain!r}")
        self._target_arg = target
        self.target = "speculos" if target == "auto" else target
        self.host = host
        self.port = port
        self.chain = chain
        self.debug_flag = debug
        self._connected: bool = False

        # State carried from a sign-psbt preset selection to the next Run.
        # Reset whenever a new preset is picked on the sign-psbt tab.
        self._sign_psbt_spec: Optional[Any] = None
        self._sign_psbt_mutator: Optional[Callable[[Any], Any]] = None
        self._sign_psbt_external_xprivs: List[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("starting...", id="status_bar")

        with TabbedContent(initial="tab_fpr", id="cmd_tabs"):
            with TabPane("get-fingerprint", id="tab_fpr"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_get_fingerprint()
                yield from self._run_bar("run_fpr")
            with TabPane("get-xpub", id="tab_xpub"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_get_xpub()
                yield from self._run_bar("run_xpub")
            with TabPane("register-wallet", id="tab_register"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_register_wallet()
                yield from self._run_bar("run_register")
            with TabPane("get-address", id="tab_addr"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_get_address()
                yield from self._run_bar("run_addr")
            with TabPane("sign-psbt", id="tab_sign_psbt"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_sign_psbt()
                yield from self._run_bar("run_sign_psbt")
            with TabPane("sign-message", id="tab_sign_msg"):
                with VerticalScroll(classes="tab-body"):
                    yield from self._compose_sign_message()
                yield from self._run_bar("run_sign_msg")

        yield RichLog(id="log", highlight=False, markup=True, wrap=False, max_lines=10_000)
        yield Footer()

    # ----- tab compose helpers ----------------------------------------------

    def _run_bar(self, button_id: str) -> ComposeResult:
        """Pinned action bar with a single Run button, kept outside the
        scrollable `.tab-body` so it stays visible no matter how tall the
        form is."""
        with Horizontal(classes="actions"):
            yield Button("Run", id=button_id, variant="primary")

    def _compose_get_fingerprint(self) -> ComposeResult:
        yield Label("Read the device's master fingerprint (GET_MASTER_FINGERPRINT, no UX).")

    def _compose_get_xpub(self) -> ComposeResult:
        with Horizontal(classes="form-row"):
            yield Label("Preset:")
            yield Select(_preset_choices(XPUB_PRESETS), value=NO_PRESET,
                         id="xpub_preset", allow_blank=False)
        with Horizontal(classes="form-row"):
            yield Label("BIP-32 path:")
            yield Input(value="m/86'/1'/0'", id="xpub_path")
        with Horizontal(classes="form-row"):
            yield Checkbox("Display & confirm on device", id="xpub_display")

    def _compose_policy_form(self, tab_id: str, presets) -> ComposeResult:
        """Shared layout for register-wallet / get-address / sign-psbt.

        A preset combobox at the top, followed by editable name / template /
        keys textarea fields. Picking a preset eagerly resolves the policy
        against the connected device and overwrites these fields; the user
        is then free to tweak any of them before Run.
        """
        with Horizontal(classes="form-row"):
            yield Label("Preset:")
            yield Select(_preset_choices(presets), value=NO_PRESET,
                         id=f"{tab_id}_preset", allow_blank=False)
        with Horizontal(classes="form-row"):
            yield Label("Wallet name:")
            yield Input(value="", id=f"{tab_id}_name",
                        placeholder="empty = standard policy, no registration")
        with Horizontal(classes="form-row"):
            yield Label("Descriptor template:")
            yield Input(value="", id=f"{tab_id}_template",
                        placeholder='e.g. wsh(or_d(pk(@0/**),pkh(@1/**)))')
        yield Label("Keys info (one [fpr/path]xpub per line, in @N order):")
        yield TextArea(id=f"{tab_id}_keys", classes="keys-area")

    def _compose_register_wallet(self) -> ComposeResult:
        yield from self._compose_policy_form("reg", self.REGISTER_PRESETS)

    def _compose_get_address(self) -> ComposeResult:
        yield from self._compose_policy_form("addr", self.ADDR_PRESETS)
        with Horizontal(classes="form-row"):
            yield Label("Change:")
            with RadioSet(id="addr_change"):
                yield RadioButton("0 (receive)", id="addr_change_0", value=True)
                yield RadioButton("1 (change)", id="addr_change_1")
        with Horizontal(classes="form-row"):
            yield Label("Address index:")
            yield Input(value="0", id="addr_index", type="integer")
        with Horizontal(classes="form-row"):
            yield Checkbox("Display & confirm on device", id="addr_display")
            yield Checkbox("Re-register (--no-cache)", id="addr_no_cache")

    def _compose_sign_psbt(self) -> ComposeResult:
        yield from self._compose_policy_form("sign", self.SIGN_PRESETS)
        yield Label(
            "PSBT (empty = generate fake; otherwise, a base64-encode PSBT or a file path):"
        )
        yield TextArea(id="sign_psbt_input")
        with Horizontal(classes="form-row"):
            yield Label("Generated inputs:")
            yield Input(value="1", id="sign_inputs", type="integer")
        with Horizontal(classes="form-row"):
            yield Label("Generated outputs:")
            yield Input(value="2", id="sign_outputs", type="integer")
        with Horizontal(classes="form-row"):
            yield Checkbox("Re-register (--no-cache)", id="sign_no_cache")

    def _compose_sign_message(self) -> ComposeResult:
        with Horizontal(classes="form-row"):
            yield Label("BIP-32 path:")
            yield Input(value="m/44'/1'/0'/0/0", id="msg_path")
        with Horizontal(classes="form-row"):
            yield Label("Message:")
            yield Input(value="hello world", id="msg_text")

    # ----- preset selection -------------------------------------------------

    @on(Select.Changed)
    def _on_preset_changed(self, event: Select.Changed) -> None:
        sel_id = event.select.id
        if not sel_id or not sel_id.endswith("_preset"):
            return
        tab_id = sel_id[: -len("_preset")]
        if event.value == NO_PRESET:
            # Picking the sentinel leaves the form alone; also clear any
            # sign-psbt-only state so a subsequent Run doesn't apply a
            # stale spec, mutator or xpriv list.
            if tab_id == "sign":
                self._sign_psbt_spec = None
                self._sign_psbt_mutator = None
                self._sign_psbt_external_xprivs = []
            return

        if tab_id == "xpub":
            preset = next((p for p in XPUB_PRESETS if p.name == event.value), None)
            if preset is None:
                return
            self._apply_xpub_preset(preset)
            return

        # Policy tabs: pick from the per-tab preset list.
        per_tab = {
            "reg": self.REGISTER_PRESETS,
            "addr": self.ADDR_PRESETS,
            "sign": self.SIGN_PRESETS,
        }.get(tab_id, [])
        preset = next((p for p in per_tab if p.name == event.value), None)
        if preset is None:
            return

        if tab_id == "sign":
            self._sign_psbt_spec = preset.psbt_spec
            self._sign_psbt_mutator = preset.psbt_mutator
            self._sign_psbt_external_xprivs = []  # filled by resolver below

        self._resolve_policy_preset(tab_id, preset)

    def _apply_xpub_preset(self, preset: XpubPreset) -> None:
        self.query_one("#xpub_path", Input).value = preset.path

    @work(thread=True, exclusive=True, group="resolve")
    def _resolve_policy_preset(self, tab_id: str, preset: PolicyPreset) -> None:
        """Resolve `preset` against the connected device and populate fields.

        Internal `KeySpec` entries trigger a get_extended_pubkey APDU and the
        resulting xpub is wrapped with the device's master fingerprint;
        external entries are derived locally from `EXTERNAL_MNEMONICS`. The
        full `[fpr/origin]xpub` lines are written into the keys textarea.
        """
        log = self.query_one("#log", RichLog)
        self.call_from_thread(
            log.write, f"[dim]resolving preset {preset.name!r}...[/]"
        )
        chain = CHAIN_BY_NAME[self.chain]

        from bitcoin_client.ledger_bitcoin import TransportClient, createClient

        client = None
        try:
            if self.target == "speculos":
                transport = TransportClient(
                    interface="tcp", server=self.host, port=self.port
                )
            else:
                transport = TransportClient(interface="hid")
            client = createClient(transport, chain=chain)
            master_fpr = client.get_master_fingerprint().hex()

            keys_info: List[str] = []
            external_xprivs: List[str] = []
            for spec in preset.keys:
                if spec.is_external:
                    keys_info.append(
                        external_key_info(chain, spec.external_index, spec.path)
                    )
                    external_xprivs.append(
                        external_xpriv(chain, spec.external_index, spec.path)
                    )
                else:
                    xpub = client.get_extended_pubkey(spec.path, display=False)
                    origin = spec.path.lstrip("m").lstrip("/")
                    line = f"[{master_fpr}/{origin}]{xpub}" if origin else xpub
                    keys_info.append(line)
        except Exception as e:
            self.call_from_thread(
                log.write,
                f"[red bold]preset resolution failed:[/] "
                f"{type(e).__name__}: {e}",
            )
            return
        finally:
            if client is not None:
                try:
                    client.stop()
                except Exception:
                    pass

        keys_text = "\n".join(keys_info)

        def populate() -> None:
            self.query_one(f"#{tab_id}_name", Input).value = preset.wallet_name
            self.query_one(f"#{tab_id}_template", Input).value = preset.template
            self.query_one(f"#{tab_id}_keys", TextArea).text = keys_text
            log.write(f"[green]✓[/] preset {preset.name!r} resolved")

        self.call_from_thread(populate)

        if tab_id == "sign":
            self._sign_psbt_external_xprivs = external_xprivs

    # ----- run-button dispatchers -------------------------------------------

    @on(Button.Pressed, "#run_fpr")
    def _run_fpr(self) -> None:
        self._dispatch("get-fingerprint", cmd_get_fingerprint)

    @on(Button.Pressed, "#run_xpub")
    def _run_xpub(self) -> None:
        path = self.query_one("#xpub_path", Input).value.strip()
        display = self.query_one("#xpub_display", Checkbox).value
        flags = f"{path}" + (" --display" if display else "")
        self._dispatch(f"get-xpub {flags}", cmd_get_xpub, path=path, display=display)

    @on(Button.Pressed, "#run_register")
    def _run_register(self) -> None:
        name, template, keys = self._read_policy_form("reg")
        flags = f'--name "{name}" --template "{template}" ({len(keys)} key(s))'
        self._dispatch(f"register-wallet {flags}", cmd_register_wallet,
                       name=name, template=template, keys=keys)

    @on(Button.Pressed, "#run_addr")
    def _run_addr(self) -> None:
        name, template, keys = self._read_policy_form("addr")
        change = self.query_one("#addr_change", RadioSet).pressed_index or 0
        index = int(self.query_one("#addr_index", Input).value or "0")
        display = self.query_one("#addr_display", Checkbox).value
        no_cache = self.query_one("#addr_no_cache", Checkbox).value
        flags = (
            f'--name "{name}" --change {change} --index {index}'
            + (" --display" if display else "")
            + (" --no-cache" if no_cache else "")
        )
        self._dispatch(f"get-address {flags}", cmd_get_address,
                       name=name, template=template, keys=keys,
                       change=change, index=index,
                       display=display, no_cache=no_cache)

    @on(Button.Pressed, "#run_sign_psbt")
    def _run_sign_psbt(self) -> None:
        name, template, keys = self._read_policy_form("sign")
        inputs = int(self.query_one("#sign_inputs", Input).value or "1")
        outputs = int(self.query_one("#sign_outputs", Input).value or "2")
        no_cache = self.query_one("#sign_no_cache", Checkbox).value

        psbt_raw = self.query_one("#sign_psbt_input", TextArea).text.strip()
        fixture: Optional[str] = None
        cleanup_tmp: Optional[Path] = None

        if not psbt_raw:
            # A preset spec defines its own inputs/outputs, so --inputs/--outputs
            # are ignored in that case.
            psbt_label = (
                "from preset spec" if self._sign_psbt_spec is not None
                else f"--inputs {inputs} --outputs {outputs}"
            )
        elif psbt_raw.startswith(PSBT_BASE64_PREFIX):
            tmp_dir = Path(tempfile.gettempdir()) / "btcapp-playground"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            tmp = tempfile.NamedTemporaryFile(
                mode="w", delete=False, dir=tmp_dir, suffix=".psbt"
            )
            tmp.write(psbt_raw + "\n")
            tmp.close()
            fixture = tmp.name
            cleanup_tmp = Path(tmp.name)
            psbt_label = f"--fixture {fixture}  (from pasted base64)"
        else:
            fixture = psbt_raw
            psbt_label = f"--fixture {fixture}"

        # Preset state: the spec/mutator only apply to *generated* PSBTs; if the
        # user supplied a fixture, leave it alone. External xprivs flow through
        # to musig2 e2e signing regardless.
        psbt_spec = self._sign_psbt_spec if fixture is None else None
        psbt_mutator = self._sign_psbt_mutator if fixture is None else None
        external_xprivs = list(self._sign_psbt_external_xprivs)

        flags = (
            f'--name "{name}" {psbt_label}'
            + (" --no-cache" if no_cache else "")
            + ("  [spec]" if psbt_spec else "")
            + (f"  [mutator={psbt_mutator.__name__}]" if psbt_mutator else "")
            + (f"  [{len(external_xprivs)} ext xpriv(s)]" if external_xprivs else "")
        )
        self._dispatch(f"sign-psbt {flags}", cmd_sign_psbt,
                       name=name, template=template, keys=keys,
                       fixture=fixture, inputs=inputs, outputs=outputs,
                       no_cache=no_cache,
                       psbt_spec=psbt_spec,
                       psbt_mutator=psbt_mutator,
                       external_xprivs=external_xprivs,
                       _cleanup_tmp=cleanup_tmp)

    @on(Button.Pressed, "#run_sign_msg")
    def _run_sign_msg(self) -> None:
        path = self.query_one("#msg_path", Input).value.strip()
        message = self.query_one("#msg_text", Input).value
        self._dispatch(f"sign-message {path} {message!r}",
                       cmd_sign_message, path=path, message=message)

    # ----- policy form reader -----------------------------------------------

    def _read_policy_form(self, tab_id: str) -> tuple[str, str, List[str]]:
        """Returns `(wallet_name, descriptor_template, keys_info)` from the
        shared name/template/keys widgets on the given policy tab.

        Trims surrounding whitespace and drops blank lines from the keys
        textarea; raises ValueError early if either of the required fields
        is empty so the dispatcher can log a clean error instead of letting
        cli.py's argparse crash."""
        name = self.query_one(f"#{tab_id}_name", Input).value.strip()
        template = self.query_one(f"#{tab_id}_template", Input).value.strip()
        keys_text = self.query_one(f"#{tab_id}_keys", TextArea).text
        keys = [k.strip() for k in keys_text.splitlines() if k.strip()]
        if not template:
            raise ValueError("descriptor template cannot be empty")
        if not keys:
            raise ValueError("at least one key required")
        return name, template, keys

    # ----- connection ------------------------------------------------------

    def _read_conn_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            target=self.target,
            host=self.host,
            port=self.port,
            chain=self.chain,
            debug=self.debug_flag,
        )

    def _set_status(self, text: str, *, ok: bool = False, error: bool = False) -> None:
        if ok:
            text = f"[green]●[/] {text}"
        elif error:
            text = f"[red]●[/] {text}"
        else:
            text = f"[yellow]●[/] {text}"
        self.query_one("#status_bar", Static).update(text)

    def on_mount(self) -> None:
        chain_label = f"chain={self.chain}"
        if self._target_arg in ("speculos", "hid"):
            self._set_status(f"forced target: {self._target_arg}  ·  {chain_label}")
            self._probe_connection(forced=True)
        else:
            self._set_status(f"probing...  ·  {chain_label}")
            self._probe_connection(forced=False)

    # ----- startup probe ---------------------------------------------------

    @work(exclusive=True, thread=True, group="probe")
    def _probe_connection(self, forced: bool) -> None:
        log = self.query_one("#log", RichLog)
        chain_obj = CHAIN_BY_NAME[self.chain]

        def status(text: str, *, ok: bool = False, error: bool = False) -> None:
            self.call_from_thread(self._set_status, text, ok=ok, error=error)

        def write(line: str) -> None:
            self.call_from_thread(log.write, line)

        def _label(target: str) -> str:
            if target == "speculos":
                return f"speculos {self.host}:{self.port}"
            return target

        if forced:
            err = _try_target(self._target_arg, self.host, self.port, chain_obj)
            if err is None:
                self.target = self._target_arg
                self._connected = True
                write(f"[green]✓[/] connected via {_label(self._target_arg)}")
                status(f"connected · {_label(self._target_arg)} · chain={self.chain}", ok=True)
                return
            self._connected = False
            write(f"[red bold]✗ {self._target_arg}:[/] {err}")
            status(f"not connected · {self._target_arg}: {err}", error=True)
            return

        err_spec = _try_target("speculos", self.host, self.port, chain_obj)
        if err_spec is None:
            self.target = "speculos"
            self._connected = True
            write(f"[green]✓[/] connected via {_label('speculos')}")
            status(f"connected · {_label('speculos')} · chain={self.chain}", ok=True)
            return

        err_hid = _try_target("hid", self.host, self.port, chain_obj)
        if err_hid is None:
            self.target = "hid"
            self._connected = True
            write("[green]✓[/] connected via USB Ledger device")
            status(f"connected · hid · chain={self.chain}", ok=True)
            return

        self.target = "speculos"
        self._connected = False
        write("[red bold]✗ no Bitcoin app found[/]")
        write(f"  speculos: {err_spec}")
        write(f"  hid:      {err_hid}")
        write(
            "[yellow]Open the Bitcoin (Test) app on the device or start speculos, "
            "then press Ctrl+R to reconnect.[/]"
        )
        status("not connected · open the Bitcoin app and press Ctrl+R", error=True)

    # ----- dispatch + worker -----------------------------------------------

    def _dispatch(self, label: str, cmd_func: Callable, *,
                  _cleanup_tmp: Optional[Path] = None,
                  **overrides) -> None:
        try:
            args = self._read_conn_args()
        except Exception as e:
            self._log_error(f"bad connection settings: {e}")
            return
        try:
            for k, v in overrides.items():
                setattr(args, k, v)
        except Exception as e:
            self._log_error(str(e))
            return
        self._run_in_worker(label, cmd_func, args, _cleanup_tmp)

    @work(exclusive=True, thread=True, group="cmd")
    def _run_in_worker(self, label: str, cmd_func: Callable,
                       args: argparse.Namespace,
                       cleanup_tmp: Optional[Path]) -> None:
        log = self.query_one("#log", RichLog)
        self.call_from_thread(log.write, f"[bold cyan]$ playground {label}[/]")

        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = _LogStream(self, log, is_err=False)
        sys.stderr = _LogStream(self, log, is_err=True)
        try:
            cmd_func(args)
        except SystemExit as e:
            if str(e) not in ("", "0", "None"):
                self.call_from_thread(log.write, f"[red bold]error:[/] {e}")
        except KeyboardInterrupt:
            self.call_from_thread(log.write, "[yellow]interrupted[/]")
        except Exception as e:
            self.call_from_thread(
                log.write, f"[red bold]error:[/] {type(e).__name__}: {e}"
            )
            for line in traceback.format_exc().rstrip("\n").split("\n"):
                self.call_from_thread(log.write, f"[red dim]{line}[/]")
        finally:
            sys.stdout.flush()  # type: ignore[union-attr]
            sys.stderr.flush()  # type: ignore[union-attr]
            sys.stdout, sys.stderr = old_out, old_err
            if cleanup_tmp is not None:
                try:
                    cleanup_tmp.unlink(missing_ok=True)
                except OSError:
                    pass
            self.call_from_thread(log.write, "")

    def _log_error(self, msg: str) -> None:
        self.query_one("#log", RichLog).write(f"[red bold]error:[/] {msg}")
        self.query_one("#log", RichLog).write("")

    # ----- right-click paste -----------------------------------------------

    def on_click(self, event: events.Click) -> None:
        """Right-click on an Input/TextArea pastes from the OS clipboard.

        Textual captures mouse events, so the terminal's native right-click
        paste never reaches us. We re-implement the gesture: read the
        clipboard via xclip/xsel/wl-paste/pbpaste in a worker thread and
        insert the text at the focused widget's cursor.
        """
        if event.button != 3:
            return
        widget = self.focused
        if not isinstance(widget, (Input, TextArea)):
            return
        self._paste_clipboard(widget)

    @work(thread=True, exclusive=True, group="paste")
    def _paste_clipboard(self, widget) -> None:
        text = _read_clipboard()
        if not text:
            return
        if isinstance(widget, Input):
            text = text.replace("\r", "").replace("\n", " ")
            self.call_from_thread(widget.insert_text_at_cursor, text)
        else:
            self.call_from_thread(widget.insert, text)

    # ----- actions ----------------------------------------------------------

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_reconnect(self) -> None:
        self._set_status(f"probing...  ·  chain={self.chain}")
        self._probe_connection(forced=(self._target_arg in ("speculos", "hid")))


def _parse_gui_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="playground-gui",
        description="Bitcoin app playground TUI.",
    )
    p.add_argument(
        "--target", choices=["auto", "speculos", "hid"], default="auto",
        help=(
            "connection target. 'auto' (default) probes speculos first, then "
            "USB; 'speculos' or 'hid' force that target."
        ),
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="speculos host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=9999,
                   help="speculos APDU port (default: 9999)")
    p.add_argument("--chain", choices=list(CHAIN_BY_NAME), default="test",
                   help="Bitcoin network (default: test)")
    p.add_argument("--debug", action="store_true",
                   help="dump APDUs on stderr")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = _parse_gui_args(argv)
    PlaygroundApp(
        target=args.target,
        host=args.host,
        port=args.port,
        chain=args.chain,
        debug=args.debug,
    ).run()


if __name__ == "__main__":
    main()
