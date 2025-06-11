import json
from pathlib import Path

import click

from scanner.malware_analyzer import MalwareAnalyzer
from scanner.link_analyzer import LinkAnalyzer
from scanner.yara_generator import YaraGenerator
from reporter.pdf_report import PDFReport
from reporter.summary_builder import SummaryBuilder

@click.group()
def cli():
    """Undertaker CLI"""
    pass

@cli.command()
@click.argument('target')
@click.option('--yara', '-y', is_flag=True, help='Generate YARA rule (malware only)')
@click.option('--pdf', '-p', is_flag=True, help='Create PDF report')
@click.option('--save-raw', is_flag=True, help='Save raw JSON output')
@click.option('--output', default=None, help='Custom output path')
def scan(target, yara, pdf, save_raw, output):
    """Analyze a file path or URL."""
    sb = SummaryBuilder()
    if target.startswith('http://') or target.startswith('https://'):
        analyzer = LinkAnalyzer(target)
        analyzer.fetch()
        indicators = analyzer.indicators()
        summary = sb.build_link_summary(indicators)
        data = {
            'summary': summary,
        }
    else:
        analyzer = MalwareAnalyzer(target)
        hashes = analyzer.hashes()
        imports = analyzer.risky_imports()
        strings = analyzer.strings()
        summary = sb.build_malware_summary(hashes, imports, strings)
        data = {
            'summary': summary,
            'hashes': hashes,
            'imports': imports,
            'strings': strings,
        }
        if yara:
            yg = YaraGenerator(Path(target).stem, hashes['md5'])
            yara_path = output or f"reports/{Path(target).stem}.yara"
            Path('reports').mkdir(exist_ok=True)
            yg.save(yara_path)
    if save_raw:
        raw_path = output or f"reports/{Path(target).stem}.json"
        Path('reports').mkdir(exist_ok=True)
        Path(raw_path).write_text(json.dumps(data, indent=2))
    if pdf:
        pdf_path = output or f"reports/{Path(target).stem}.pdf"
        Path('reports').mkdir(exist_ok=True)
        PDFReport().create(data, pdf_path)
    click.echo(summary)

if __name__ == '__main__':
    cli()
