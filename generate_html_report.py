#!/usr/bin/env python3
import json
import os
import sys
from collections import defaultdict
import subprocess
import datetime

def load_compliance_matrix():
    """Load the compliance matrix from the JSON file."""
    try:
        with open("docs/compliance_matrix.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Compliance matrix file not found.")
        return {}

def extract_test_results():
    """Extract test results from the pytest output."""
    try:
        # Run pytest and capture output
        result = subprocess.run(
            ["python3", "-m", "pytest", "tests/test_compliance.py", "-v"],
            capture_output=True,
            text=True
        )
        
        # Parse the output to get test results
        test_results = {}
        for line in result.stdout.split('\n'):
            if "::test_" in line:
                parts = line.split('::')
                if len(parts) >= 3:
                    test_name = parts[2].split(' ')[0]
                    if "PASSED" in line:
                        status = "passed"
                    elif "FAILED" in line:
                        status = "failed"
                    elif "SKIPPED" in line:
                        status = "skipped"
                    else:
                        status = "unknown"
                    test_results[test_name] = status
        
        return test_results
    except Exception as e:
        print(f"Error running tests: {e}")
        return {}

def extract_test_compliance_map():
    """Extract compliance information from test file content."""
    test_compliance_map = {}
    
    try:
        with open("tests/test_compliance.py", "r") as f:
            content = f.read()
        
        # Split content by test methods
        import re
        test_methods = re.findall(r'def (test_[^(]+)\([^)]+\):\s+"""([^"]+)"""', content, re.DOTALL)
        
        for test_name, docstring in test_methods:
            frameworks = {
                "FSBP": [],
                "CIS AWS 3.0.0": [],
                "AWS SSB": []
            }
            
            for line in docstring.strip().split("\n"):
                line = line.strip()
                if line.startswith("- FSBP:"):
                    frameworks["FSBP"] = [ref.strip() for ref in line.replace("- FSBP:", "").split(",")]
                elif line.startswith("- CIS AWS 3.0.0:"):
                    frameworks["CIS AWS 3.0.0"] = [ref.strip() for ref in line.replace("- CIS AWS 3.0.0:", "").split(",")]
                elif line.startswith("- AWS SSB:"):
                    frameworks["AWS SSB"] = [ref.strip() for ref in line.replace("- AWS SSB:", "").split(",")]
            
            test_compliance_map[test_name] = {
                "description": docstring.strip().split("\n")[0].strip(),
                "frameworks": frameworks
            }
        
        return test_compliance_map
    except Exception as e:
        print(f"Error extracting test compliance map: {e}")
        return {}

def generate_coverage_data(test_compliance_map, compliance_matrix, test_results=None):
    """Generate coverage data by mapping tests to compliance controls."""
    # Create a mapping from framework references to controls
    framework_to_control = {}
    for control_name, control_data in compliance_matrix.items():
        for framework, refs in control_data["frameworks"].items():
            for ref in refs:
                if ref:
                    key = (framework, ref)
                    if key not in framework_to_control:
                        framework_to_control[key] = []
                    framework_to_control[key].append(control_name)
    
    # Map tests to controls
    test_to_controls = defaultdict(set)
    for test_name, test_data in test_compliance_map.items():
        for framework, refs in test_data["frameworks"].items():
            for ref in refs:
                key = (framework, ref)
                if key in framework_to_control:
                    for control in framework_to_control[key]:
                        test_to_controls[test_name].add(control)
    
    # Map controls to tests
    control_to_tests = defaultdict(set)
    for test_name, controls in test_to_controls.items():
        for control in controls:
            control_to_tests[control].add(test_name)
    
    # Calculate coverage
    covered_controls = set(control_to_tests.keys())
    all_controls = set(compliance_matrix.keys())
    uncovered_controls = all_controls - covered_controls
    
    coverage_percentage = (len(covered_controls) / len(all_controls)) * 100 if all_controls else 0
    
    # Add test status if provided
    test_status = {}
    if test_results:
        for test_name in test_compliance_map.keys():
            if test_name in test_results:
                test_status[test_name] = test_results[test_name]
            else:
                test_status[test_name] = "unknown"
    
    # Categorize untested controls
    untested_controls = {}
    for control in uncovered_controls:
        # Check if control is in the runtime-dependent category
        if any(ref in ["CloudTrail.2", "GuardDuty.1", "SecurityHub.1", "IAM.8", "CloudWatch.2"] 
               for framework in compliance_matrix[control]["frameworks"] 
               for ref in compliance_matrix[control]["frameworks"][framework]):
            untested_controls[control] = "runtime-dependent"
        # Check if control is in the residual risk category
        elif any(ref in ["IAM.4", "CIS 1.13", "CIS 1.4", "SSB.IAM.8", "SSB.DAT.9", "SSB.DAT.10", "SSB.IR.7", "SSB.IR.9", "SSB.NET.10"] 
                for framework in compliance_matrix[control]["frameworks"] 
                for ref in compliance_matrix[control]["frameworks"][framework]):
            untested_controls[control] = "residual-risk"
        # Check if control is in the implementation gap category
        elif any(ref in ["SNS.1", "SSB.LOG.10", "SSB.IR.8", "SSB.NET.9", "EC2.15", "IAM.8"] 
                for framework in compliance_matrix[control]["frameworks"] 
                for ref in compliance_matrix[control]["frameworks"][framework]):
            untested_controls[control] = "implementation-gap"
        # Check if control is in the testing framework limitations category
        elif any(ref in ["CIS 3.3", "CIS 3.7", "CIS 5.5", "IAM.16", "CIS 4.1", "CIS 4.2", "CIS 4.3", "CIS 4.4", "CIS 4.5", "CIS 4.6", "CIS 4.7", "CIS 4.8", "CIS 4.9", "CIS 4.10", "CIS 4.11", "CIS 4.12", "CIS 4.13", "CIS 4.14", "CIS 4.15", "CIS 4.16"] 
                for framework in compliance_matrix[control]["frameworks"] 
                for ref in compliance_matrix[control]["frameworks"][framework]):
            untested_controls[control] = "testing-limitations"
        # Check if control is in the manual verification category
        elif any(ref in ["CIS 1.18", "IAM.7", "IAM.3", "Config.3"] 
                for framework in compliance_matrix[control]["frameworks"] 
                for ref in compliance_matrix[control]["frameworks"][framework]):
            untested_controls[control] = "manual-verification"
        else:
            untested_controls[control] = "other"
    
    return {
        "test_to_controls": dict(test_to_controls),
        "control_to_tests": dict(control_to_tests),
        "covered_controls": list(covered_controls),
        "uncovered_controls": list(uncovered_controls),
        "coverage_percentage": coverage_percentage,
        "test_compliance_map": test_compliance_map,
        "compliance_matrix": compliance_matrix,
        "test_status": test_status,
        "untested_controls": untested_controls
    }

def generate_html_report(coverage_data):
    """Generate an HTML report from the coverage data."""
    
    # Calculate statistics
    total_controls = len(coverage_data['compliance_matrix'])
    covered_controls = len(coverage_data['covered_controls'])
    uncovered_controls = len(coverage_data['uncovered_controls'])
    
    passed_tests = sum(1 for status in coverage_data["test_status"].values() if status == "passed")
    failed_tests = sum(1 for status in coverage_data["test_status"].values() if status == "failed")
    skipped_tests = sum(1 for status in coverage_data["test_status"].values() if status == "skipped")
    unknown_tests = sum(1 for status in coverage_data["test_status"].values() if status == "unknown")
    
    # Group uncovered controls by reason
    reason_groups = defaultdict(list)
    for control in sorted(coverage_data["uncovered_controls"]):
        reason = coverage_data.get("untested_controls", {}).get(control, "other")
        reason_groups[reason].append(control)
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Test Coverage Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #0066cc;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }}
        .summary-box {{
            background-color: #f5f5f5;
            border-radius: 5px;
            padding: 15px;
            width: 48%;
        }}
        .progress-container {{
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            margin: 10px 0;
        }}
        .progress-bar {{
            height: 100%;
            border-radius: 10px;
            background-color: #4CAF50;
            text-align: center;
            color: white;
            line-height: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .passed {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .failed {{
            color: #f44336;
            font-weight: bold;
        }}
        .skipped {{
            color: #ff9800;
            font-weight: bold;
        }}
        .unknown {{
            color: #9e9e9e;
            font-style: italic;
        }}
        .reason {{
            font-style: italic;
            color: #666;
        }}
        .reason-runtime {{
            background-color: #e3f2fd;
        }}
        .reason-residual {{
            background-color: #fff8e1;
        }}
        .reason-implementation {{
            background-color: #f1f8e9;
        }}
        .reason-testing {{
            background-color: #fce4ec;
        }}
        .reason-manual {{
            background-color: #e8eaf6;
        }}
        .reason-other {{
            background-color: #f5f5f5;
        }}
        .footer {{
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 0.8em;
            color: #666;
        }}
        .test-link {{
            text-decoration: none;
            color: #0066cc;
            border-bottom: 1px dotted #0066cc;
        }}
        .test-link:hover {{
            border-bottom: 1px solid #0066cc;
        }}
        .tooltip {{
            position: relative;
            display: inline-block;
            cursor: help;
        }}
        .tooltip .tooltiptext {{
            visibility: hidden;
            width: 300px;
            background-color: #555;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 10px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -150px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.9em;
            line-height: 1.4;
        }}
        .tooltip:hover .tooltiptext {{
            visibility: visible;
            opacity: 1;
        }}
        .test-details {{
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }}
        .test-details h3 {{
            margin-top: 0;
        }}
        .test-details pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <h1>Compliance Test Coverage Report</h1>
    <p>Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <div class="summary">
        <div class="summary-box">
            <h2>Coverage Summary</h2>
            <p>Overall Coverage: <strong>{coverage_data['coverage_percentage']:.1f}%</strong></p>
            <div class="progress-container">
                <div class="progress-bar" style="width: {coverage_data['coverage_percentage']}%">
                    {coverage_data['coverage_percentage']:.1f}%
                </div>
            </div>
            <p>Total Controls: {total_controls}</p>
            <p>Covered Controls: {covered_controls}</p>
            <p>Uncovered Controls: {uncovered_controls}</p>
        </div>
        
        <div class="summary-box">
            <h2>Test Status Summary</h2>
            <p>Total Tests: {len(coverage_data["test_status"])}</p>
            <p><span class="passed">✓ Passed:</span> {passed_tests}</p>
            <p><span class="failed">✗ Failed:</span> {failed_tests}</p>
            <p><span class="skipped">⚠ Skipped:</span> {skipped_tests}</p>
            <p><span class="unknown">? Unknown:</span> {unknown_tests}</p>
        </div>
    </div>
    
    <h2>Covered Controls</h2>
    <table>
        <tr>
            <th>Control</th>
            <th>Description</th>
            <th>Framework References</th>
            <th>Tests</th>
        </tr>
"""
    
    # Add rows for covered controls
    for control in sorted(coverage_data["covered_controls"]):
        control_data = coverage_data["compliance_matrix"][control]
        framework_refs = []
        for framework, refs in control_data["frameworks"].items():
            if refs:
                framework_refs.append(f"{framework}: {', '.join(refs)}")
        
        tests = coverage_data["control_to_tests"].get(control, [])
        test_list = []
        for test in tests:
            status = coverage_data.get("test_status", {}).get(test, "unknown")
            status_class = status
            status_icon = "✓" if status == "passed" else "✗" if status == "failed" else "⚠" if status == "skipped" else "?"
            
            # Get test description if available
            test_description = coverage_data["test_compliance_map"].get(test, {}).get("description", "")
            
            # Create tooltip with test description
            tooltip = f"""<div class="tooltip">
                <a href="#test-{test}" class="test-link">{test}</a>
                <span class="tooltiptext">{test_description}</span>
            </div>"""
            
            test_list.append(f'<span class="{status_class}">{status_icon} {tooltip}</span>')
        
        html += f"""
        <tr>
            <td>{control}</td>
            <td>{control_data['description']}</td>
            <td>{'; '.join(framework_refs)}</td>
            <td>{'<br>'.join(test_list)}</td>
        </tr>"""
    
    html += """
    </table>
    
    <h2>Uncovered Controls</h2>
    <table>
        <tr>
            <th>Control</th>
            <th>Description</th>
            <th>Framework References</th>
            <th>Reason</th>
            <th>Documentation</th>
        </tr>
"""
    
    # Define reason mappings
    reason_text = {
        "runtime-dependent": "Runtime verification required",
        "residual-risk": "Documented residual risk",
        "implementation-gap": "Implementation gap",
        "testing-limitations": "Testing framework limitations",
        "manual-verification": "Manual verification required",
        "other": "Not implemented"
    }
    
    reason_class = {
        "runtime-dependent": "reason-runtime",
        "residual-risk": "reason-residual",
        "implementation-gap": "reason-implementation",
        "testing-limitations": "reason-testing",
        "manual-verification": "reason-manual",
        "other": "reason-other"
    }
    
    reason_doc_link = {
        "runtime-dependent": "untested_controls.md#1-runtime-dependent-controls",
        "residual-risk": "untested_controls.md#2-documented-residual-risk-controls",
        "implementation-gap": "untested_controls.md#3-implementation-gaps",
        "testing-limitations": "untested_controls.md#4-testing-framework-limitations",
        "manual-verification": "untested_controls.md#5-manual-verification-required",
        "other": "untested_controls.md"
    }
    
    # Add rows for uncovered controls
    for reason, controls in reason_groups.items():
        for control in sorted(controls):
            control_data = coverage_data["compliance_matrix"][control]
            framework_refs = []
            for framework, refs in control_data["frameworks"].items():
                if refs:
                    framework_refs.append(f"{framework}: {', '.join(refs)}")
            
            html += f"""
        <tr class="{reason_class.get(reason, 'reason-other')}">
            <td>{control}</td>
            <td>{control_data['description']}</td>
            <td>{'; '.join(framework_refs)}</td>
            <td class="reason">{reason_text.get(reason, "Unknown")}</td>
            <td><a href="{reason_doc_link.get(reason, 'untested_controls.md')}">Documentation</a></td>
        </tr>"""
    
    html += """
    </table>
    
    <h2>Reason Categories for Uncovered Controls</h2>
    
    <h3>Runtime Verification Required</h3>
    <p>These controls can only be verified at runtime after deployment, not during CDK synthesis testing.</p>
    <p>See <a href="untested_controls.md#1-runtime-dependent-controls">Untested Controls</a> for details.</p>
    
    <h3>Documented Residual Risk</h3>
    <p>These controls are explicitly documented as residual risk in the compliance matrix.</p>
    <p>See <a href="untested_controls.md#2-documented-residual-risk-controls">Untested Controls</a> for details.</p>
    
    <h3>Implementation Gap</h3>
    <p>These controls are partially implemented but have gaps that prevent complete testing.</p>
    <p>See <a href="untested_controls.md#3-implementation-gaps">Untested Controls</a> for details.</p>
    
    <h3>Testing Framework Limitations</h3>
    <p>These controls are difficult to test due to limitations in the testing framework.</p>
    <p>See <a href="untested_controls.md#4-testing-framework-limitations">Untested Controls</a> for details.</p>
    
    <h3>Manual Verification Required</h3>
    <p>These controls require manual verification procedures.</p>
    <p>See <a href="untested_controls.md#5-manual-verification-required">Untested Controls</a> for details.</p>
    
    <h2>Test Implementation Details</h2>
    <p>This section provides details on how each test validates compliance controls.</p>
    """
    
    # Add test implementation details
    for test_name, test_data in coverage_data["test_compliance_map"].items():
        description = test_data.get("description", "")
        frameworks = test_data.get("frameworks", {})
        framework_refs = []
        for framework, refs in frameworks.items():
            if refs:
                framework_refs.append(f"{framework}: {', '.join(refs)}")
        
        # Get test status
        status = coverage_data.get("test_status", {}).get(test_name, "unknown")
        status_class = status
        status_text = "Passed" if status == "passed" else "Failed" if status == "failed" else "Skipped" if status == "skipped" else "Unknown"
        
        # Get controls covered by this test
        controls = coverage_data["test_to_controls"].get(test_name, [])
        
        html += f"""
    <div class="test-details" id="test-{test_name}">
        <h3>{test_name}</h3>
        <p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>
        <p><strong>Description:</strong> {description}</p>
        <p><strong>Framework References:</strong> {', '.join(framework_refs)}</p>
        <p><strong>Controls Covered:</strong> {', '.join(sorted(controls))}</p>
        <p><strong>Implementation:</strong></p>
        <pre>
# Test implementation for {test_name}
# This test validates the following controls: {', '.join(sorted(controls))}
# Framework references: {', '.join(framework_refs)}

def {test_name}(self):
    \"\"\"
    {description}
    \"\"\"
    # Test implementation details can be found in tests/test_compliance.py
        </pre>
        <p><a href="https://github.com/kalleeh/aws-msb-cdk/blob/main/tests/test_compliance.py" target="_blank">View full test implementation on GitHub</a></p>
    </div>
    """
    
    html += """
    <div class="footer">
        <p>Generated by AWS MSB CDK Compliance Testing Framework</p>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    # Load compliance matrix
    compliance_matrix = load_compliance_matrix()
    
    # Extract compliance information from tests
    test_compliance_map = extract_test_compliance_map()
    
    # Run tests and get results
    test_results = extract_test_results()
    
    # Generate coverage data
    coverage_data = generate_coverage_data(test_compliance_map, compliance_matrix, test_results)
    
    # Generate HTML report
    html_report = generate_html_report(coverage_data)
    
    # Write report to file
    with open("docs/compliance_report.html", "w") as f:
        f.write(html_report)
    
    print(f"HTML Compliance report generated: docs/compliance_report.html")
    print(f"Overall coverage: {coverage_data['coverage_percentage']:.1f}%")
    
    # Print test results summary
    passed = sum(1 for status in test_results.values() if status == "passed")
    failed = sum(1 for status in test_results.values() if status == "failed")
    skipped = sum(1 for status in test_results.values() if status == "skipped")
    print(f"Tests: {passed} passed, {failed} failed, {skipped} skipped")