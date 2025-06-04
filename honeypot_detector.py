import sys
import json
import requests
from web3 import Web3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# ------------- CONFIGURATION -------------
BSC_RPC = "https://bsc-dataseed.binance.org/"
ETH_RPC = "https://rpc.ankr.com/eth"
BSCSCAN_API_KEY = "3QA7THP9BWWQPHPPCZXVM81QD479SNDIC9"
ETHERSCAN_API_KEY = ""  # Add one if you want Ethereum support
# -----------------------------------------

console = Console()

PATTERNS = {
    "onlyWhitelistedSell": {
        "desc": "Possible sell restriction: Only whitelisted addresses can sell.",
        "detect": lambda src: "whitelist" in src and ("sell" in src or "transfer" in src),
    },
    "blacklist": {
        "desc": "Blacklist detected: Certain addresses can be blocked.",
        "detect": lambda src: "blacklist" in src,
    },
    "taxOnSell": {
        "desc": "Token applies taxes on sells (check how high).",
        "detect": lambda src: "tax" in src and "sell" in src,
    },
    "disableSell": {
        "desc": "Possible sell blocking (revert, require, or block in sell logic).",
        "detect": lambda src: "revert" in src and ("sell" in src or "transfer" in src),
    },
    "antiBot": {
        "desc": "Anti-bot or anti-sniper logic present.",
        "detect": lambda src: "bot" in src or "anti" in src,
    }
}

def get_contract_source(address, chain='bsc'):
    if chain == 'bsc':
        url = f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={address}&apikey={BSCSCAN_API_KEY}"
    else:
        url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={ETHERSCAN_API_KEY}"
    r = requests.get(url)
    result = r.json()
    if not result["result"] or result["result"][0]["SourceCode"] == "":
        raise Exception("Source code not verified or not available")
    return result["result"][0]["SourceCode"]

def detect_honeypot_patterns(source_code):
    # Normalize source to lower case for matching
    src = source_code.lower()
    findings = []
    for name, pattern in PATTERNS.items():
        if pattern["detect"](src):
            findings.append({"pattern": name, "explanation": pattern["desc"]})
    return findings

def print_report(address, chain, findings):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Pattern", style="bold")
    table.add_column("Explanation", style="")

    if findings:
        for f in findings:
            table.add_row(f["pattern"], f["explanation"])
        console.print(Panel.fit(table, title="🚨 Honeypot Patterns Detected!", border_style="red"))
    else:
        console.print(Panel("[bold green]No obvious honeypot patterns found![/bold green]", title="Safe?", border_style="green"))

    console.print("\n[cyan]Exported JSON report for this contract![/cyan]\n")

def export_json(address, chain, findings):
    result_json = {
        "contract": address,
        "chain": chain,
        "honeypot_patterns": findings,
    }
    filename = f"{address}_honeypot_report.json"
    with open(filename, "w") as f:
        json.dump(result_json, f, indent=2)
    return filename

def main():
    if len(sys.argv) < 3:
        console.print("[yellow]Usage:[/yellow] python honeypot_detector.py <contract_address> <bsc|eth>")
        sys.exit(1)
    contract = sys.argv[1]
    chain = sys.argv[2].lower()

    console.print(Panel(f"Scanning [bold]{contract}[/bold] on [bold cyan]{chain.upper()}[/bold cyan]...",
                        title="Smart Contract Honeypot Detector", style="blue"))

    console.print("[white]Fetching contract source...[/white]")
    try:
        source = get_contract_source(contract, chain)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)
    console.print("[green]Contract source fetched.[/green]")

    console.print("[white]Scanning for honeypot patterns...[/white]")
    findings = detect_honeypot_patterns(source)
    print_report(contract, chain, findings)
    filename = export_json(contract, chain, findings)
    console.print(f"[bold blue]Report written to:[/bold blue] [underline]{filename}[/underline]")

    # Pro tips
    if not findings:
        console.print("\n[green]Tip: No patterns found, but always test trades with small amounts first![/green]")
    else:
        console.print("\n[red]Warning: At least one suspicious pattern detected! Investigate before trading![/red]")

if __name__ == "__main__":
    main()
