# -*- coding: utf-8 -*-
# Header Change Notifier - Burp Suite Extension
# Version: 2.0.0
# Author: Mohamed Essam
# Description: Detects and alerts when HTTP response headers change between requests (Passive Scanner)

from burp import IBurpExtender, ITab, IScannerCheck, IScanIssue
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, Font
from javax.swing import JPanel, JTabbedPane, JTable, JScrollPane, JButton, JLabel, JTextField, JCheckBox, JOptionPane, JFileChooser
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing import SwingUtilities
from java.io import File
from java.net import URL
from java.util import Date
import threading
import time
import csv

class BurpExtender(IBurpExtender, ITab, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Extension metadata
        self.EXTENSION_NAME = "Header Change Notifier"
        self.VERSION = "2.0.0"
        
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        # Initialize data structures
        self._header_storage = {}
        self._detected_changes = []
        self._lock = threading.Lock()
        self._tracked_headers = {
            'set-cookie': True,
            'content-security-policy': True,
            'x-frame-options': True,
            'x-content-type-options': True,
            'referrer-policy': True,
            'strict-transport-security': True,
            'x-xss-protection': True,
            'access-control-allow-origin': True,
            'server': True,
            'x-powered-by': True
        }
        
        self._init_ui()
        
        # Register as passive scanner
        callbacks.registerScannerCheck(self)
        
        callbacks.addSuiteTab(self)
        
        print("[+] Header Change Notifier v{} loaded successfully!".format(self.VERSION))
        print("[+] Using passive scanner implementation for better scope control")
    
    def _init_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._tabbed_pane = JTabbedPane()
        self._create_changes_tab()
        self._create_settings_tab()
        self._create_about_tab()
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)
    
    def _create_changes_tab(self):
        changes_panel = JPanel(BorderLayout())
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        clear_btn = JButton("Clear All", actionPerformed=self._clear_all_data)
        clear_btn.setPreferredSize(Dimension(100, 30))
        export_btn = JButton("Export CSV", actionPerformed=self._export_to_csv)
        export_btn.setPreferredSize(Dimension(100, 30))
        
        self._stats_label = JLabel("Changes detected: 0 | URLs monitored: 0")
        self._stats_label.setFont(Font("Dialog", Font.PLAIN, 12))
        
        top_panel.add(clear_btn)
        top_panel.add(export_btn)
        top_panel.add(JLabel("  |  "))
        top_panel.add(self._stats_label)
        
        self._changes_table_model = DefaultTableModel()
        self._changes_table_model.setColumnIdentifiers([
            "Timestamp", "URL", "Header", "Old Value", "New Value", "Risk Level"
        ])
        
        self._changes_table = JTable(self._changes_table_model)
        self._changes_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        column_widths = [150, 300, 200, 250, 250, 100]
        for i, width in enumerate(column_widths):
            self._changes_table.getColumnModel().getColumn(i).setPreferredWidth(width)
        
        risk_renderer = RiskLevelCellRenderer()
        self._changes_table.getColumnModel().getColumn(5).setCellRenderer(risk_renderer)
        
        table_scroll = JScrollPane(self._changes_table)
        table_scroll.setPreferredSize(Dimension(800, 400))
        
        changes_panel.add(top_panel, BorderLayout.NORTH)
        changes_panel.add(table_scroll, BorderLayout.CENTER)
        
        self._tabbed_pane.addTab("Header Changes", changes_panel)
    
    def _create_settings_tab(self):
        settings_panel = JPanel(BorderLayout())
        
        main_settings = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        title_label = JLabel("Header Tracking Configuration")
        title_label.setFont(Font("Dialog", Font.BOLD, 16))
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.insets = Insets(10, 10, 20, 10)
        main_settings.add(title_label, gbc)
        
        self._header_checkboxes = {}
        row = 1
        
        for header, enabled in self._tracked_headers.items():
            gbc.gridx = 0
            gbc.gridy = row
            gbc.gridwidth = 1
            gbc.insets = Insets(5, 20, 5, 10)
            gbc.anchor = GridBagConstraints.WEST
            
            checkbox = JCheckBox(header.replace('-', ' ').title(), enabled)
            self._header_checkboxes[header] = checkbox
            main_settings.add(checkbox, gbc)
            
            gbc.gridx = 1
            gbc.insets = Insets(5, 10, 5, 20)
            description = self._get_header_description(header)
            desc_label = JLabel(description)
            desc_label.setFont(Font("Dialog", Font.ITALIC, 11))
            main_settings.add(desc_label, gbc)
            
            row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(20, 20, 10, 20)
        custom_label = JLabel("Add Custom Header:")
        custom_label.setFont(Font("Dialog", Font.BOLD, 12))
        main_settings.add(custom_label, gbc)
        
        row += 1
        gbc.gridy = row
        gbc.insets = Insets(5, 20, 5, 20)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        custom_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._custom_header_field = JTextField(20)
        add_custom_btn = JButton("Add", actionPerformed=self._add_custom_header)
        custom_panel.add(self._custom_header_field)
        custom_panel.add(add_custom_btn)
        main_settings.add(custom_panel, gbc)
        
        row += 1
        gbc.gridy = row
        gbc.insets = Insets(30, 20, 20, 20)
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        
        save_btn = JButton("Save Settings", actionPerformed=self._save_settings)
        save_btn.setPreferredSize(Dimension(150, 35))
        main_settings.add(save_btn, gbc)
        
        settings_panel.add(main_settings, BorderLayout.NORTH)
        self._tabbed_pane.addTab("Settings", settings_panel)
    
    def _create_about_tab(self):
        about_panel = JPanel(BorderLayout())
        
        about_content = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        title = JLabel("Header Change Notifier v{}".format(self.VERSION))
        title.setFont(Font("Dialog", Font.BOLD, 18))
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(20, 20, 10, 20)
        about_content.add(title, gbc)
        
        description = """
        This extension monitors HTTP response headers and alerts you when they change
        between requests to the same URL. It's particularly useful for:
        
        - Detecting security misconfigurations
        - Monitoring CSP policy changes
        - Tracking cookie attribute modifications
        - Identifying server changes during penetration testing
        
        Features:
        + Real-time header change detection via passive scanning
        + Respects Burp Suite scope settings
        + Customizable header tracking
        + Risk level assessment
        + CSV export functionality
        + Clean, professional interface
        
        Usage:
        1. Configure which headers to track in the Settings tab
        2. Set your target scope in Burp Suite
        3. Run an active or passive scan, or use the Proxy
        4. Check the Header Changes tab and Scanner Issues for detected modifications
        5. Export results for reporting
        
        Note: This extension uses passive scanning, so it respects your configured
        scope and integrates seamlessly with Burp's scanning workflow.
        """
        
        desc_label = JLabel("<html><div style='width: 500px;'>{}</div></html>".format(
            description.replace('\n', '<br>')
        ))
        desc_label.setFont(Font("Dialog", Font.PLAIN, 12))
        gbc.gridy = 1
        gbc.insets = Insets(10, 20, 20, 20)
        about_content.add(desc_label, gbc)
        
        about_panel.add(about_content, BorderLayout.NORTH)
        self._tabbed_pane.addTab("About", about_panel)
    
    def _get_header_description(self, header):
        descriptions = {
            'set-cookie': 'Session cookies and their security attributes',
            'content-security-policy': 'Content Security Policy rules',
            'x-frame-options': 'Clickjacking protection settings',
            'x-content-type-options': 'MIME type sniffing protection',
            'referrer-policy': 'Referrer information control',
            'strict-transport-security': 'HTTPS enforcement policy',
            'x-xss-protection': 'XSS filtering settings',
            'access-control-allow-origin': 'CORS origin permissions',
            'server': 'Web server identification',
            'x-powered-by': 'Technology stack disclosure'
        }
        return descriptions.get(header, 'Custom security header')
    
    # IScannerCheck implementation
    def doPassiveScan(self, baseRequestResponse):
        """
        Passive scan implementation - called by Burp for each request/response
        """
        try:
            response = baseRequestResponse.getResponse()
            if response is None:
                return None
            
            response_info = self._helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            
            url = str(baseRequestResponse.getUrl())
            url_path = URL(url).getPath() or '/'
            base_url = "{}://{}{}".format(
                URL(url).getProtocol(),
                URL(url).getHost(),
                url_path
            )
            
            # Process headers and detect changes
            issues = self._process_headers_passive(base_url, headers, baseRequestResponse)
            
            return issues if issues else None
            
        except Exception as e:
            print("[-] Error in passive scan: {}".format(str(e)))
            return None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Active scan not implemented for this extension
        """
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """
        Custom issue consolidation - keep the most recent issue
        """
        # If the issues are for the same URL and header, only keep the newer one
        if (existingIssue.getUrl() == newIssue.getUrl() and 
            existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1  # Keep existing issue
        
        return 0  # Keep both issues
    
    def _process_headers_passive(self, url, headers, baseRequestResponse):
        """
        Process headers and return list of IScanIssue objects if changes detected
        """
        issues = []
        
        with self._lock:
            # Extract tracked headers
            current_headers = {}
            for header in headers[1:]:
                if ':' in header:
                    name, value = header.split(':', 1)
                    name = name.strip().lower()
                    value = value.strip()
                    
                    if name in self._tracked_headers and self._tracked_headers[name]:
                        current_headers[name] = value
            
            # Compare with previous headers
            if url in self._header_storage:
                previous_headers = self._header_storage[url]['headers']
                change_records = self._compare_headers_passive(url, previous_headers, current_headers)
                
                # Create IScanIssue objects for each change
                for change_record in change_records:
                    issue = HeaderChangeScanIssue(
                        baseRequestResponse,
                        self._helpers,
                        self._callbacks,
                        change_record
                    )
                    issues.append(issue)
                    
                    # Also add to UI table
                    self._detected_changes.append(change_record)
                    SwingUtilities.invokeLater(lambda cr=change_record: self._add_change_to_table(cr))
            
            # Store current headers
            self._header_storage[url] = {
                'headers': current_headers,
                'timestamp': time.time()
            }
            
            # Update UI stats
            SwingUtilities.invokeLater(self._update_stats)
        
        return issues if issues else None
    
    def _compare_headers_passive(self, url, old_headers, new_headers):
        """
        Compare headers and return list of change records
        """
        changes = []
        all_headers = set(old_headers.keys()) | set(new_headers.keys())
        
        for header in all_headers:
            old_value = old_headers.get(header, '')
            new_value = new_headers.get(header, '')
            
            if old_value != new_value:
                change_record = {
                    'timestamp': Date(),
                    'url': url,
                    'header': header,
                    'old_value': old_value,
                    'new_value': new_value,
                    'risk_level': self._assess_risk_level(header, old_value, new_value)
                }
                changes.append(change_record)
        
        return changes
    
    def _assess_risk_level(self, header, old_value, new_value):
        """Assess the risk level of a header change"""
        # Critical: Security headers removed
        critical_headers = ['content-security-policy', 'x-frame-options']
        if header in critical_headers:
            if old_value and not new_value:
                return 'Critical'
            return 'High'
        
        # High: Security cookie attributes weakened
        high_risk_headers = ['strict-transport-security', 'set-cookie']
        if header in high_risk_headers:
            if 'secure' in old_value.lower() and 'secure' not in new_value.lower():
                return 'High'
            if 'httponly' in old_value.lower() and 'httponly' not in new_value.lower():
                return 'High'
            return 'Medium'
        
        # Medium: Other security headers modified
        medium_risk_headers = ['referrer-policy', 'x-content-type-options']
        if header in medium_risk_headers:
            return 'Medium'
        
        return 'Low'
    
    def _add_change_to_table(self, change_record):
        """Add a change record to the UI table"""
        row_data = [
            change_record['timestamp'].toString(),
            change_record['url'],
            change_record['header'],
            change_record['old_value'][:100] + ('...' if len(change_record['old_value']) > 100 else ''),
            change_record['new_value'][:100] + ('...' if len(change_record['new_value']) > 100 else ''),
            change_record['risk_level']
        ]
        self._changes_table_model.addRow(row_data)
    
    def _update_stats(self):
        """Update statistics label"""
        changes_count = len(self._detected_changes)
        urls_count = len(self._header_storage)
        self._stats_label.setText(
            "Changes detected: {} | URLs monitored: {}".format(changes_count, urls_count)
        )
    
    def _clear_all_data(self, event):
        """Clear all stored data and UI"""
        with self._lock:
            self._header_storage.clear()
            self._detected_changes[:] = []
            self._changes_table_model.setRowCount(0)
            self._update_stats()
        
        JOptionPane.showMessageDialog(
            self._main_panel,
            "All data cleared successfully!",
            "Clear Complete",
            JOptionPane.INFORMATION_MESSAGE
        )
    
    def _export_to_csv(self, event):
        """Export detected changes to CSV file"""
        if not self._detected_changes:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No changes to export!",
                "Export Error",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        file_chooser = JFileChooser()
        file_chooser.setSelectedFile(File("header_changes.csv"))
        
        if file_chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            try:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                with open(file_path, 'wb') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'URL', 'Header', 'Old Value', 'New Value', 'Risk Level'])
                    
                    for change in self._detected_changes:
                        writer.writerow([
                            str(change['timestamp']),
                            change['url'],
                            change['header'],
                            change['old_value'],
                            change['new_value'],
                            change['risk_level']
                        ])
                
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Changes exported successfully to:\n{}".format(file_path),
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
                
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Export failed: {}".format(str(e)),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )
    
    def _add_custom_header(self, event):
        """Add a custom header to track"""
        header_name = self._custom_header_field.getText().strip().lower()
        
        if not header_name:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Please enter a header name!",
                "Invalid Input",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        if header_name in self._tracked_headers:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Header '{}' is already being tracked!".format(header_name),
                "Duplicate Header",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        self._tracked_headers[header_name] = True
        self._custom_header_field.setText("")
        
        JOptionPane.showMessageDialog(
            self._main_panel,
            "Header '{}' added successfully!\nRestart the extension to see it in the settings.".format(header_name),
            "Header Added",
            JOptionPane.INFORMATION_MESSAGE
        )
    
    def _save_settings(self, event):
        """Save header tracking settings"""
        for header, checkbox in self._header_checkboxes.items():
            self._tracked_headers[header] = checkbox.isSelected()
        
        JOptionPane.showMessageDialog(
            self._main_panel,
            "Settings saved successfully!",
            "Settings Saved",
            JOptionPane.INFORMATION_MESSAGE
        )
    
    # ITab implementation
    def getTabCaption(self):
        """Return tab caption"""
        return self.EXTENSION_NAME
    
    def getUiComponent(self):
        """Return UI component"""
        return self._main_panel


class RiskLevelCellRenderer(DefaultTableCellRenderer):
    """Custom cell renderer for risk level column"""
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        
        if not isSelected:
            if value == "Critical":
                component.setBackground(Color(255, 200, 200))
            elif value == "High":
                component.setBackground(Color(255, 230, 200))
            elif value == "Medium":
                component.setBackground(Color(255, 255, 200))
            else:
                component.setBackground(Color(230, 255, 230))
        
        return component


class HeaderChangeScanIssue(IScanIssue):
    """Custom scan issue for header changes"""
    
    def __init__(self, baseRequestResponse, helpers, callbacks, change_record):
        self._baseRequestResponse = baseRequestResponse
        self._helpers = helpers
        self._callbacks = callbacks
        self._change_record = change_record
        self._url = baseRequestResponse.getUrl()
        self._httpService = baseRequestResponse.getHttpService()
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return "HTTP Header Change Detected: {}".format(self._change_record['header'])
    
    def getIssueType(self):
        return 0x08000000  # Extension-generated issue
    
    def getSeverity(self):
        risk_level = self._change_record['risk_level']
        if risk_level == "Critical":
            return "High"
        elif risk_level == "High":
            return "Medium"
        elif risk_level == "Medium":
            return "Low"
        else:
            return "Information"
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return """
        <p>The HTTP response header <b>{}</b> has changed between requests to the same URL.</p>
        <p>This could indicate:</p>
        <ul>
            <li>Security misconfigurations</li>
            <li>Server changes or updates</li>
            <li>Load balancer behavior</li>
            <li>Potential security issues</li>
        </ul>
        <p>Security headers are critical for protecting against various web attacks. 
        Changes to these headers should be investigated to ensure they don't introduce vulnerabilities.</p>
        """.format(self._change_record['header'])
    
    def getRemediationBackground(self):
        return """
        <p>Review the header changes carefully:</p>
        <ul>
            <li>Ensure security headers are not weakened or removed</li>
            <li>Verify that cookie attributes remain secure (HttpOnly, Secure, SameSite)</li>
            <li>Check that CSP policies are not relaxed unnecessarily</li>
            <li>Confirm that changes are intentional and documented</li>
        </ul>
        """
    
    def getIssueDetail(self):
        old_val = self._change_record['old_value']
        new_val = self._change_record['new_value']
        
        # Truncate long values for readability
        if len(old_val) > 200:
            old_val = old_val[:200] + "..."
        if len(new_val) > 200:
            new_val = new_val[:200] + "..."
        
        return """
        <p><b>Header:</b> {}</p>
        <p><b>Risk Level:</b> {}</p>
        <p><b>Previous Value:</b></p>
        <pre>{}</pre>
        <p><b>New Value:</b></p>
        <pre>{}</pre>
        <p><b>Detected:</b> {}</p>
        """.format(
            self._change_record['header'],
            self._change_record['risk_level'],
            old_val if old_val else "(header was not present)",
            new_val if new_val else "(header removed)",
            self._change_record['timestamp'].toString()
        )
    
    def getRemediationDetail(self):
        header = self._change_record['header']
        
        recommendations = {
            'content-security-policy': 'Ensure CSP directives are not weakened. Avoid using unsafe-inline or unsafe-eval.',
            'x-frame-options': 'Maintain DENY or SAMEORIGIN to prevent clickjacking attacks.',
            'set-cookie': 'Ensure cookies have Secure, HttpOnly, and SameSite attributes.',
            'strict-transport-security': 'Keep HSTS enabled with appropriate max-age value.',
            'x-content-type-options': 'Maintain "nosniff" to prevent MIME type confusion attacks.',
        }
        
        specific = recommendations.get(header, 'Review the header change and ensure it aligns with security best practices.')
        
        return "<p>{}</p>".format(specific)
    
    def getHttpMessages(self):
        return [self._baseRequestResponse]
    
    def getHttpService(self):
        return self._httpService
