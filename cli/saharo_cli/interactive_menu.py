from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
import os
import selectors
import shlex
import signal
import subprocess
import sys
import threading
import fcntl
import struct
import termios
from typing import Iterable

import click
import pyte
import typer
from prompt_toolkit import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import ConditionalContainer, HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Frame


@dataclass
class CommandNode:
    name: str
    tokens: list[str]
    help_text: str
    is_group: bool
    children: list["CommandNode"] = field(default_factory=list)


@dataclass
class MenuEntry:
    title: str
    value: str | None
    node: CommandNode | None
    selectable: bool = True
    is_group: bool = False


def build_command_tree(app: typer.Typer) -> CommandNode:
    click_command = typer.main.get_command(app)
    root_name = click_command.name or "saharo"
    return _build_node(click_command, root_name, [])


def _build_node(command: click.Command, name: str, tokens: list[str]) -> CommandNode:
    help_text = _clean_help(command.short_help or command.help or "")
    is_group = isinstance(command, click.Group)
    node = CommandNode(name=name, tokens=tokens, help_text=help_text, is_group=is_group)

    if is_group:
        group = command  # type: ignore[assignment]
        for child_name, child_cmd in sorted(group.commands.items()):
            if getattr(child_cmd, "hidden", False):
                continue
            if child_name == "":
                if isinstance(child_cmd, click.Group):
                    for sub_name, sub_cmd in sorted(child_cmd.commands.items()):
                        if getattr(sub_cmd, "hidden", False):
                            continue
                        node.children.append(_build_node(sub_cmd, sub_name, tokens + [sub_name]))
                else:
                    child_token = child_cmd.name or ""
                    if child_token:
                        node.children.append(_build_node(child_cmd, child_token, tokens + [child_token]))
            else:
                node.children.append(_build_node(child_cmd, child_name, tokens + [child_name]))

    return node


def run_interactive_menu(app: typer.Typer) -> list[str] | None:
    root = build_command_tree(app)
    stack: list[CommandNode] = [root]
    selected_index = 0
    search_query = ""
    result: list[str] | None = None
    node_index = _index_nodes(root)
    leaf_nodes = _flatten_nodes(root)
    mode = "menu"
    terminal_exit_code: int | None = None
    terminal_running = False
    terminal_proc: subprocess.Popen[bytes] | None = None
    terminal_master_fd: int | None = None
    terminal_thread: threading.Thread | None = None
    terminal_stop = threading.Event()
    terminal_cmd_text = ""
    args_input = ""
    pending_tokens: list[str] | None = None
    terminal_screen: pyte.Screen | None = None
    terminal_stream: pyte.Stream | None = None
    terminal_cols = 80
    terminal_rows = 20
    scrollback: deque[str] = deque(maxlen=60)

    def build_entries() -> list[MenuEntry]:
        current = stack[-1]
        entries: list[MenuEntry] = []
        if len(stack) > 1:
            entries.append(MenuEntry(title=".. Back", value="__back__", node=None))

        groups = [child for child in _sorted_children(current.children) if child.is_group]
        commands = [child for child in _sorted_children(current.children) if not child.is_group]

        if search_query:
            q = search_query.lower()
            matches = [n for n in leaf_nodes if q in n.name.lower() or q in "/".join(n.tokens).lower()]
            if matches:
                entries.append(MenuEntry(title=f"Results ({len(matches)})", value=None, node=None, selectable=False))
                for n in matches:
                    path = "/".join(n.tokens) if n.tokens else n.name
                    label = path
                    entries.append(MenuEntry(title=label, value=path, node=n, is_group=n.is_group))
            else:
                entries.append(MenuEntry(title="No matches", value=None, node=None, selectable=False))
            # Keep Exit at the bottom (root only).
            if len(stack) == 1:
                entries.append(MenuEntry(title="", value=None, node=None, selectable=False))
                entries.append(MenuEntry(title="Exit", value="__exit__", node=None))
            return entries

        if groups:
            entries.append(MenuEntry(title="Groups", value=None, node=None, selectable=False))
            for child in groups:
                label = f"{child.name}/"
                if child.help_text:
                    label = f"{label} — {child.help_text}"
                entries.append(MenuEntry(title=label, value=child.name, node=child, is_group=True))
        if commands:
            entries.append(MenuEntry(title="Commands", value=None, node=None, selectable=False))
            for child in commands:
                label = child.name
                if child.help_text:
                    label = f"{label} — {child.help_text}"
                entries.append(MenuEntry(title=label, value=child.name, node=child, is_group=False))

        # Put Exit at the very bottom, after a blank line (root only).
        if len(stack) == 1:
            entries.append(MenuEntry(title="", value=None, node=None, selectable=False))
            entries.append(MenuEntry(title="Exit", value="__exit__", node=None))
        return entries

    def clamp_index(entries: list[MenuEntry]) -> None:
        nonlocal selected_index
        if not entries:
            selected_index = 0
            return
        if selected_index < 0:
            selected_index = 0
        if selected_index >= len(entries):
            selected_index = len(entries) - 1
        if entries and not entries[selected_index].selectable:
            selected_index = _next_selectable(entries, selected_index, 1)

    def get_header() -> FormattedText:
        return [("class:header", "Saharo Interactive CLI")]

    def get_search() -> FormattedText:
        if mode == "terminal":
            if terminal_cmd_text:
                return [("class:search", terminal_cmd_text)]
            return [("class:search_dim", "Command: -")]
        if mode == "args":
            if args_input:
                return [("class:search", f"Args: {args_input}")]
            return [("class:search_dim", "Args: (optional)")]
        if search_query:
            return [("class:search", f"Search: {search_query}")]
        return [("class:search_dim", "Type to search…")]

    def get_menu() -> FormattedText:
        entries = build_entries()
        clamp_index(entries)
        lines: list[tuple[str, str]] = []
        for idx, entry in enumerate(entries):
            is_selected = idx == selected_index
            if entry.selectable:
                prefix = "▶ " if is_selected else "  "
                style = "class:cursor" if is_selected else ("class:group" if entry.is_group else "class:item")
            else:
                prefix = ""
                style = "class:separator"
            lines.append((style, prefix))
            lines.append((style, entry.title))
            lines.append(("", "\n"))
        if lines:
            lines.pop()
        return lines

    def get_help() -> FormattedText:
        entries = build_entries()
        if not entries:
            return []
        clamp_index(entries)
        entry = entries[selected_index]
        if not entry.node:
            return [("class:help_dim", " ")]
        node = entry.node
        path = " ".join(["saharo", *node.tokens]) if node.tokens else "saharo"
        help_text = node.help_text or ""
        if help_text:
            return [
                ("class:help_path", path),
                ("", "\n\n"),
                ("class:help", help_text),
            ]
        return [("class:help_path", path)]

    def get_footer() -> FormattedText:
        if mode == "terminal":
            if terminal_running:
                return [
                    ("class:footer", "Ctrl+C "),
                    ("class:footer_dim", "interrupt  "),
                    ("class:footer", "Esc "),
                    ("class:footer_dim", "send Esc"),
                ]
            return [
                ("class:footer", "Enter "),
                ("class:footer_dim", "back to menu  "),
                ("class:footer", "Esc "),
                ("class:footer_dim", "back to menu"),
            ]
        if mode == "args":
            return [
                ("class:footer", "Enter "),
                ("class:footer_dim", "run  "),
                ("class:footer", "Esc "),
                ("class:footer_dim", "cancel"),
            ]
        return [
            ("class:footer", "Enter "),
            ("class:footer_dim", "run  "),
            ("class:footer", "Alt+Enter "),
            ("class:footer_dim", "args  "),
            ("class:footer", "Ctrl+J "),
            ("class:footer_dim", "args  "),
            ("class:footer", "Esc "),
            ("class:footer_dim", "back/clear"),
        ]

    def move_selection(delta: int) -> None:
        nonlocal selected_index
        entries = build_entries()
        if not entries:
            return
        selected_index = _next_selectable(entries, selected_index, delta)
        app.invalidate()

    def go_back() -> None:
        nonlocal selected_index
        if len(stack) > 1:
            stack.pop()
            selected_index = 0
            sync_layout()
            app.invalidate()
        else:
            app.exit(result=None)

    def update_search(char: str | None, *, backspace: bool = False) -> None:
        nonlocal search_query, selected_index
        if backspace:
            search_query = search_query[:-1]
        elif char:
            search_query += char
        selected_index = 0
        sync_layout()
        app.invalidate()

    def update_args(char: str | None, *, backspace: bool = False) -> None:
        nonlocal args_input
        if backspace:
            args_input = args_input[:-1]
        elif char:
            args_input += char
        app.invalidate()

    def append_search_text(text: str) -> None:
        nonlocal search_query, selected_index
        if not text:
            return
        filtered = "".join(ch for ch in text if ch.isprintable())
        if not filtered:
            return
        search_query += filtered
        selected_index = 0
        sync_layout()
        app.invalidate()

    def append_args_text(text: str) -> None:
        nonlocal args_input
        if not text:
            return
        filtered = "".join(ch for ch in text if ch.isprintable() or ch == " ")
        if not filtered:
            return
        args_input += filtered
        app.invalidate()

    def render_terminal() -> FormattedText:
        if terminal_screen is None:
            status = "Running..." if terminal_running else "No output."
            return [("class:terminal_dim", status)]
        snapshot = _snapshot_screen()
        text = "\n\n".join([*scrollback, snapshot]) if snapshot else "\n\n".join(scrollback)
        if terminal_running:
            return [("class:terminal", text)]
        code = terminal_exit_code if terminal_exit_code is not None else 0
        return [
            ("class:terminal", text),
            ("class:terminal_dim", f"\n\n[process exited with code {code}]"),
        ]

    def set_mode(next_mode: str) -> None:
        nonlocal mode
        mode = next_mode
        sync_layout()
        app.invalidate()

    def _ensure_terminal_screen() -> None:
        nonlocal terminal_screen, terminal_stream
        terminal_screen = pyte.Screen(terminal_cols, terminal_rows)
        terminal_stream = pyte.Stream(terminal_screen)

    def _snapshot_screen() -> str:
        if terminal_screen is None:
            return ""
        lines = list(terminal_screen.display)
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines)

    def _stash_screen() -> None:
        snap = _snapshot_screen()
        if snap:
            scrollback.append(snap)

    def _feed_terminal(data: bytes) -> None:
        if not data:
            return
        hard_clear = False
        marker = b"\x1b]999;SAHARO_CLEAR\x07"
        if marker in data:
            hard_clear = True
            data = data.replace(marker, b"")
        if hard_clear:
            scrollback.clear()
            _ensure_terminal_screen()
        if b"\x1b[J" in data or b"\x1b[2J" in data or b"\x1b[3J" in data:
            if not hard_clear:
                _stash_screen()
        while True:
            idx = data.find(b"\x1b[6n")
            if idx == -1:
                break
            before = data[:idx]
            after = data[idx + 4 :]
            if before:
                _feed_terminal(before)
            send_to_terminal(b"\x1b[1;1R")
            data = after
        if terminal_stream is None:
            return
        try:
            terminal_stream.feed(data.decode(errors="replace"))
        except Exception:
            return
        app.invalidate()

    def _terminal_reader() -> None:
        nonlocal terminal_running, terminal_exit_code
        master_fd = terminal_master_fd
        if master_fd is None:
            return
        sel = selectors.DefaultSelector()
        sel.register(master_fd, selectors.EVENT_READ)
        while not terminal_stop.is_set():
            if terminal_proc is not None and terminal_proc.poll() is not None:
                break
            events = sel.select(timeout=0.1)
            for key, _ in events:
                try:
                    data = os.read(key.fd, 4096)
                except OSError:
                    data = b""
                if not data:
                    continue
                _feed_terminal(data)
        if terminal_proc is not None:
            terminal_exit_code = terminal_proc.poll()
        terminal_running = False
        terminal_stop.set()
        app.invalidate()

    def start_terminal(tokens: list[str]) -> None:
        nonlocal terminal_proc, terminal_master_fd, terminal_thread, terminal_running, terminal_exit_code, terminal_cmd_text, search_query
        terminal_exit_code = None
        terminal_running = True
        terminal_stop.clear()
        search_query = ""
        set_mode("terminal")
        scrollback.clear()
        cmd = [sys.executable, "-m", "saharo_cli.entrypoint", *tokens]
        terminal_cmd_text = "Command: " + " ".join(["saharo", *tokens])
        _ensure_terminal_screen()
        master_fd, slave_fd = os.openpty()
        terminal_master_fd = master_fd
        _set_pty_size(slave_fd, terminal_rows, terminal_cols)
        env = os.environ.copy()
        env["SAHARO_INTERACTIVE"] = "1"
        terminal_proc = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
            close_fds=True,
            env=env,
        )
        os.close(slave_fd)
        terminal_thread = threading.Thread(target=_terminal_reader, daemon=True)
        terminal_thread.start()

    def send_to_terminal(data: bytes) -> None:
        if terminal_master_fd is None:
            return
        try:
            os.write(terminal_master_fd, data)
        except OSError:
            return

    def _cleanup_terminal() -> None:
        nonlocal terminal_proc, terminal_master_fd
        terminal_stop.set()
        if terminal_proc is not None:
            try:
                terminal_proc.terminate()
            except Exception:
                pass
            terminal_proc = None
        if terminal_master_fd is not None:
            try:
                os.close(terminal_master_fd)
            except OSError:
                pass
            terminal_master_fd = None

    kb = KeyBindings()

    @kb.add(Keys.ControlC, eager=True)
    def _ctrl_c(_event) -> None:
        if mode == "terminal" and terminal_proc is not None:
            try:
                os.killpg(os.getpgid(terminal_proc.pid), signal.SIGINT)
            except Exception:
                pass
            return
        app.exit(result=None)

    @kb.add(Keys.Up, eager=True, filter=Condition(lambda: mode == "menu"))
    def _up(_event) -> None:
        move_selection(-1)

    @kb.add(Keys.Down, eager=True, filter=Condition(lambda: mode == "menu"))
    def _down(_event) -> None:
        move_selection(1)

    @kb.add(Keys.Backspace, eager=True, filter=Condition(lambda: mode == "menu"))
    def _backspace(_event) -> None:
        # Only edits search. Navigation/back happens on Esc.
        if search_query:
            update_search(None, backspace=True)

    @kb.add(Keys.Escape, eager=True, filter=Condition(lambda: mode == "menu"))
    def _escape(_event) -> None:
        nonlocal search_query, selected_index
        if search_query:
            search_query = ""
            selected_index = 0
            sync_layout()
            app.invalidate()
        else:
            go_back()

    # Intentionally no 'q' quit binding (user requested Ctrl+C / Esc only).

    @kb.add(Keys.Enter, eager=True, filter=Condition(lambda: mode == "menu"))
    def _enter(_event) -> None:
        nonlocal selected_index, result, search_query, pending_tokens, args_input
        entries = build_entries()
        if not entries:
            return
        clamp_index(entries)
        entry = entries[selected_index]
        if not entry.selectable:
            return
        if entry.value == "__exit__":
            app.exit(result=None)
            return
        if entry.value == "__back__":
            go_back()
            return
        node = entry.node
        if not node:
            return
        if node.is_group:
            # In global search mode jump directly to the group path.
            if search_query:
                stack[:] = _stack_for_tokens(root, node_index, node.tokens)
                search_query = ""
                sync_layout()
            else:
                stack.append(node)
                sync_layout()
            selected_index = 0
            app.invalidate()
            return
        start_terminal(node.tokens)

    @kb.add(Keys.Any, filter=Condition(lambda: mode == "menu"))
    def _text(event) -> None:
        char = event.key_sequence[0].key
        if isinstance(char, str) and len(char) == 1 and char.isprintable():
            update_search(char)

    @kb.add(Keys.BracketedPaste, filter=Condition(lambda: mode == "menu"))
    def _paste_menu(event) -> None:
        text = getattr(event, "data", "") or ""
        append_search_text(text)

    @kb.add("escape", "enter", eager=True, filter=Condition(lambda: mode == "menu"))
    @kb.add(Keys.ControlJ, eager=True, filter=Condition(lambda: mode == "menu"))
    def _ctrl_j(_event) -> None:
        nonlocal selected_index, pending_tokens, args_input, search_query
        entries = build_entries()
        if not entries:
            return
        clamp_index(entries)
        entry = entries[selected_index]
        if not entry.selectable:
            return
        if entry.value in {"__exit__", "__back__"}:
            return
        node = entry.node
        if not node:
            return
        if node.is_group:
            if search_query:
                stack[:] = _stack_for_tokens(root, node_index, node.tokens)
                search_query = ""
                sync_layout()
            else:
                stack.append(node)
                sync_layout()
            selected_index = 0
            app.invalidate()
            return
        pending_tokens = node.tokens
        args_input = ""
        set_mode("args")

    @kb.add(Keys.Backspace, eager=True, filter=Condition(lambda: mode == "args"))
    def _args_backspace(_event) -> None:
        if args_input:
            update_args(None, backspace=True)

    @kb.add(Keys.Escape, eager=True, filter=Condition(lambda: mode == "args"))
    def _args_escape(_event) -> None:
        set_mode("menu")

    @kb.add(Keys.Enter, eager=True, filter=Condition(lambda: mode == "args"))
    def _args_enter(_event) -> None:
        nonlocal pending_tokens, args_input
        tokens = pending_tokens or []
        extra: list[str] = []
        if args_input.strip():
            try:
                extra = shlex.split(args_input)
            except ValueError:
                extra = args_input.split()
        pending_tokens = None
        args_input = ""
        start_terminal(tokens + extra)

    @kb.add(Keys.Any, filter=Condition(lambda: mode == "args"))
    def _args_text(event) -> None:
        char = event.key_sequence[0].key
        if isinstance(char, str) and len(char) == 1 and char.isprintable():
            update_args(char)

    @kb.add(Keys.BracketedPaste, filter=Condition(lambda: mode == "args"))
    def _paste_args(event) -> None:
        text = getattr(event, "data", "") or ""
        append_args_text(text)

    @kb.add(Keys.Enter, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_enter(_event) -> None:
        nonlocal terminal_cmd_text
        if not terminal_running:
            _cleanup_terminal()
            terminal_cmd_text = ""
            set_mode("menu")
            return
        send_to_terminal(b"\r")

    @kb.add(Keys.Escape, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_escape(_event) -> None:
        if terminal_running:
            send_to_terminal(b"\x1b")
        else:
            _cleanup_terminal()
            set_mode("menu")

    @kb.add(Keys.Backspace, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_backspace(_event) -> None:
        send_to_terminal(b"\x7f")

    @kb.add(Keys.Tab, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_tab(_event) -> None:
        send_to_terminal(b"\t")

    @kb.add(Keys.Up, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_up(_event) -> None:
        send_to_terminal(b"\x1b[A")

    @kb.add(Keys.Down, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_down(_event) -> None:
        send_to_terminal(b"\x1b[B")

    @kb.add(Keys.Right, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_right(_event) -> None:
        send_to_terminal(b"\x1b[C")

    @kb.add(Keys.Left, eager=True, filter=Condition(lambda: mode == "terminal"))
    def _term_left(_event) -> None:
        send_to_terminal(b"\x1b[D")

    @kb.add(Keys.Any, filter=Condition(lambda: mode == "terminal"))
    def _term_text(event) -> None:
        char = event.key_sequence[0].key
        if isinstance(char, str) and len(char) == 1:
            send_to_terminal(char.encode())

    @kb.add(Keys.BracketedPaste, filter=Condition(lambda: mode == "terminal"))
    def _paste_term(event) -> None:
        text = getattr(event, "data", "") or ""
        if text:
            send_to_terminal(text.encode())

    header = FormattedTextControl(text=get_header, focusable=False, show_cursor=False)
    search = FormattedTextControl(text=get_search, focusable=False, show_cursor=False)
    menu = FormattedTextControl(text=get_menu, focusable=True, show_cursor=False)
    help_panel = FormattedTextControl(text=get_help, focusable=False, show_cursor=False)
    footer = FormattedTextControl(text=get_footer, focusable=False, show_cursor=False)
    terminal_panel = FormattedTextControl(text=render_terminal, focusable=False, show_cursor=False)

    style = Style.from_dict(
        {
            "": "bg:default fg:default",
            "frame": "bg:default",
            "frame.border": "fg:gray",
            "frame.label": "fg:gray",
            "header": "ansiwhite bold",
            "search": "fg:#e6a700 bg:default",
            "search_dim": "fg:gray bg:default",
            "item": "",
            "cursor": "ansiyellow bold",
            "group": "ansiblue",
            "separator": "ansiblack bold",
            "help_path": "ansicyan bold",
            "help": "",
            "help_dim": "ansiblack",
            "footer": "ansiwhite bold",
            "footer_dim": "ansiblack",
            "terminal": "",
            "terminal_dim": "ansiblack",
        }
    )

    menu_frame = Frame(Window(menu, always_hide_cursor=True), title="Commands", style="class:frame")
    help_frame = Frame(
        Window(help_panel, wrap_lines=True, always_hide_cursor=True),
        title="Info",
        style="class:frame",
        width=Dimension.exact(44),
    )
    terminal_frame = Frame(
        Window(terminal_panel, wrap_lines=True, always_hide_cursor=True),
        title="Output",
        style="class:frame",
    )

    root_container = HSplit(
        [
            Window(header, height=1, always_hide_cursor=True, style="bg:default"),
            Window(search, height=1, always_hide_cursor=True, style="bg:default"),
            ConditionalContainer(
                VSplit(
                    [
                        menu_frame,
                        help_frame,
                    ]
                ),
                filter=Condition(lambda: mode in {"menu", "args"}),
            ),
            ConditionalContainer(
                terminal_frame,
                filter=Condition(lambda: mode == "terminal"),
            ),
            Window(footer, height=1, always_hide_cursor=True, style="bg:default"),
        ],
        align="TOP",
    )
    layout = Layout(root_container, focused_element=menu)
    app = Application(layout=layout, key_bindings=kb, style=style, full_screen=False)

    def sync_layout() -> None:
        entries = build_entries()
        menu_lines = max(1, len(entries))
        try:
            term_rows = os.get_terminal_size().lines
        except OSError:
            term_rows = 24
        available = max(6, term_rows - 3)
        if mode == "terminal":
            panel_height = available
        else:
            panel_height = min(menu_lines + 2, available)
        frame_dim = Dimension(min=panel_height, max=panel_height, preferred=panel_height)
        menu_frame.height = frame_dim
        help_frame.height = frame_dim
        terminal_frame.height = frame_dim
        total = 1 + 1 + panel_height + 1
        root_container.height = Dimension(min=total, max=total, preferred=total)
        nonlocal terminal_cols, terminal_rows
        try:
            cols = os.get_terminal_size().columns
        except OSError:
            cols = 80
        terminal_cols = max(20, cols - 4)
        terminal_rows = max(5, panel_height - 2)
        if terminal_screen is not None:
            _ensure_terminal_screen()
        if terminal_master_fd is not None:
            _set_pty_size(terminal_master_fd, terminal_rows, terminal_cols)
            if terminal_proc is not None:
                try:
                    os.killpg(os.getpgid(terminal_proc.pid), signal.SIGWINCH)
                except Exception:
                    pass

    sync_layout()
    return app.run()


def _sorted_children(children: Iterable[CommandNode]) -> list[CommandNode]:
    return sorted(children, key=lambda n: n.name)


def _clean_help(text: str) -> str:
    if not text:
        return ""
    line = text.strip().splitlines()[0]
    cleaned = line.strip()
    if cleaned.lower().startswith("usage:"):
        return ""
    return cleaned


def _next_selectable(entries: list[MenuEntry], start: int, delta: int) -> int:
    if not entries:
        return 0
    count = len(entries)
    idx = start
    for _ in range(count):
        idx = (idx + delta) % count
        if entries[idx].selectable:
            return idx
    return start


def _flatten_nodes(root: CommandNode) -> list[CommandNode]:
    out: list[CommandNode] = []
    stack: list[CommandNode] = [root]
    while stack:
        node = stack.pop()
        if node is not root:
            out.append(node)
        for child in reversed(node.children):
            stack.append(child)
    return out


def _index_nodes(root: CommandNode) -> dict[tuple[str, ...], CommandNode]:
    idx: dict[tuple[str, ...], CommandNode] = {tuple(root.tokens): root}
    for node in _flatten_nodes(root):
        idx[tuple(node.tokens)] = node
    return idx


def _stack_for_tokens(root: CommandNode, index: dict[tuple[str, ...], CommandNode], tokens: list[str]) -> list[CommandNode]:
    stack: list[CommandNode] = [root]
    cur: list[str] = []
    for t in tokens:
        cur.append(t)
        node = index.get(tuple(cur))
        if not node:
            break
        stack.append(node)
    return stack


def _set_pty_size(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        return
