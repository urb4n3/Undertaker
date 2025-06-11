from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

class PDFReport:
    """Generate PDF reports from Jinja2 templates."""

    def __init__(self, template_dir: str = 'templates'):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def create(self, data: dict, output: str) -> Path:
        tmpl = self.env.get_template('report.html')
        html = tmpl.render(**data)
        out_path = Path(output)
        HTML(string=html).write_pdf(str(out_path))
        return out_path
