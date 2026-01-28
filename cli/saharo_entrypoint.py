from __future__ import annotations


def main() -> None:
    # абсолютный импорт пакета
    from saharo_cli.entrypoint import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
