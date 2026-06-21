"""Shared output module for the Domain Probe CLI tool.

Provides formatted terminal output using Rich, including banners, tables,
key-value pairs, status messages, and JSON export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def print_banner(domain: str) -> None:
    """Display a Rich panel banner with the tool title and target domain.

    Args:
        domain: The domain name being probed (e.g. ``example.com``).
    """
    panel = Panel(
        f"[bold]Target:[/bold] {domain}",
        title="Domain Probe",
        border_style="blue",
        title_align="left",
    )
    console.print(panel)


def print_section(title: str) -> None:
    """Print a section header using bold cyan text and a rule underline.

    Args:
        title: Section heading text.
    """
    console.rule(f"[bold cyan]{title}")


def print_table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    """Render a Rich table with the given header and data rows.

    Args:
        title: Table caption shown above the table.
        columns: Column header names.
        rows: Data rows; each inner list must have the same length as *columns*.
    """
    table = Table(title=title, show_header=True, header_style="bold")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)


def print_key_value(data: dict[str, Any]) -> None:
    """Print a dictionary as aligned key-value pairs.

    Keys are rendered in green, values in default white.

    Args:
        data: Mapping whose items will be printed one per line.
    """
    if not data:
        return
    max_key_len = max(len(str(k)) for k in data)
    for key, value in data.items():
        text = Text()
        text.append(f"{key:<{max_key_len}}  ", style="green")
        text.append(str(value))
        console.print(text)


def print_warning(msg: str) -> None:
    """Print a warning message in yellow.

    Args:
        msg: The warning text.
    """
    console.print(f"[yellow]⚠ {msg}[/yellow]")


def print_error(msg: str) -> None:
    """Print an error message in bold red.

    Args:
        msg: The error text.
    """
    console.print(f"[bold red]✖ {msg}[/bold red]")


def print_success(msg: str) -> None:
    """Print a success message in green.

    Args:
        msg: The success text.
    """
    console.print(f"[green]✔ {msg}[/green]")


def export_json(data: dict[str, Any], filepath: str | Path) -> None:
    """Write a dictionary to a JSON file with indentation and confirm on stdout.

    Args:
        data: Serializable dictionary to export.
        filepath: Destination path (will be overwritten if it exists).
    """
    path = Path(filepath)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print_success(f"JSON exported to {path.resolve()}")
