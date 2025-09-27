from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime
from colorama import Fore, init

class PentestReporter:
    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        self.styles = getSampleStyleSheet()
        self.elements = []
        
        # Store results in simple format
        self.results = {
            'sql_injection': [],
            'xss': [],
            'csrf': [],
            'pii': []
        }
    
    def add_sqli_finding(self, form_action, method, payload):
        """Add SQL Injection finding"""
        self.results['sql_injection'].append({
            'form_action': form_action,
            'method': method,
            'payload': payload,
        })
    
    def add_xss_finding(self, form_action, method, payload):
        """Add XSS finding"""
        self.results['xss'].append({
            'form_action': form_action,
            'method': method,
            'payload': payload,
        })
    
    def add_csrf_finding(self, form_action, method):
        """Add CSRF finding"""
        self.results['csrf'].append({
            'form_action': form_action,
            'method': method,
        })
    
    def add_pii_finding(self, pii_type, value):
        """Add PII finding"""
        self.results['pii'].append({
            'type': pii_type,
            'value': value,
        })
    
    def create_report(self):
        """Generate the PDF report"""
        doc = SimpleDocTemplate(self.output_file, pagesize=A4)
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.darkblue,
            alignment=1
        )
        self.elements.append(Paragraph("SECURITY VULNERABILITY REPORT", title_style))
        self.elements.append(Spacer(1, 20))
        
        # Target Info
        info_style = self.styles['Normal']
        self.elements.append(Paragraph(f"<b>Target:</b> {self.target_url}", info_style))
        self.elements.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        self.elements.append(Spacer(1, 30))
        
        # Executive Summary
        self._add_summary()
        self.elements.append(Spacer(1, 20))
        
        # Vulnerability Details
        self._add_vulnerability_section("SQL INJECTION", self.results['sql_injection'], self._format_sqli_table)
        self._add_vulnerability_section("CROSS-SITE SCRIPTING (XSS)", self.results['xss'], self._format_xss_table)
        self._add_vulnerability_section("CSRF VULNERABILITIES", self.results['csrf'], self._format_csrf_table)
        self._add_vulnerability_section("PII EXPOSURE", self.results['pii'], self._format_pii_table)
        
        # Generate PDF
        doc.build(self.elements)
        print( Fore.GREEN + "[+] Report generated:",Fore.RESET + f" {self.output_file}")
    
    def _add_summary(self):
        """Add executive summary"""
        total_vulns = sum(len(vulns) for vulns in self.results.values())
        
        summary_text = f"""
        <b>EXECUTIVE SUMMARY</b><br/><br/>
        <b>Total Vulnerabilities Found:</b> {total_vulns}<br/>
        <b>SQL Injection:</b> {len(self.results['sql_injection'])}<br/>
        <b>XSS:</b> {len(self.results['xss'])}<br/>
        <b>CSRF:</b> {len(self.results['csrf'])}<br/>
        <b>PII Exposure:</b> {len(self.results['pii'])}<br/>
        """
        self.elements.append(Paragraph(summary_text, self.styles['Normal']))
    
    def _add_vulnerability_section(self, title, findings, table_formatter):
        """Add a vulnerability section"""
        if not findings:
            return
            
        # Section header
        header_style = ParagraphStyle(
            'VulnHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.darkred
        )
        self.elements.append(Paragraph(title, header_style))
        self.elements.append(Spacer(1, 10))
        
        # Create table
        table_data = table_formatter(findings)
        table = Table(table_data, colWidths=[1.5*72, 2*72, 3*72, 2.5*72])  # Convert to points
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        self.elements.append(table)
        self.elements.append(Spacer(1, 20))
    
    def _format_sqli_table(self, findings):
        """Format SQL Injection findings table"""
        table_data = [['Form Action', 'Method', 'Payload']]
        for finding in findings:
            table_data.append([
                finding['form_action'],
                finding['method'],
                finding['payload'][:30] + '...' if len(finding['payload']) > 30 else finding['payload'],
            ])
        return table_data
    
    def _format_xss_table(self, findings):
        """Format XSS findings table"""
        table_data = [['Form Action', 'Method', 'Payload']]
        for finding in findings:
            table_data.append([
                finding['form_action'],
                finding['method'],
                finding['payload'][:30] + '...' if len(finding['payload']) > 30 else finding['payload']
            ])
        return table_data
    
    def _format_csrf_table(self, findings):
        """Format CSRF findings table"""
        table_data = [['Form Action', 'Method']]
        for finding in findings:
            table_data.append([
                finding['form_action'],
                finding['method'],
            ])
        return table_data
    
    def _format_pii_table(self, findings):
        """Format PII findings table"""
        table_data = [['Type', 'Value', 'Context']]
        for finding in findings:
            # Mask sensitive data for report
            value = finding['value']
            if finding['type'] in ['email', 'ssn', 'phone']:
                value = value[:3] + '***' + value[-2:]  # Partial masking
            table_data.append([
                finding['type'].upper(),
                value,
            ])
        return table_data
