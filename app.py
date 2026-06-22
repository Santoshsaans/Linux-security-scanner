# app.py - Flask Web Dashboard for Linux Security Scanner

from flask import Flask, render_template, jsonify, send_file, request
import json
import os
from datetime import datetime
from scanner import run_full_scan, save_report_txt, save_report_csv, save_report_json

app = Flask(__name__)

# Store latest scan results
latest_results = None

@app.route('/')
def dashboard():
    """Render the main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Run a new security scan and return results"""
    global latest_results
    try:
        # Run the scan
        results = run_full_scan()
        latest_results = results
        
        # Save reports
        save_report_txt(results)
        save_report_csv(results)
        save_report_json(results)
        
        # Return JSON response
        return jsonify({
            'success': True,
            'results': results,
            'summary': results['summary']
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/latest')
def get_latest():
    """Get the latest scan results"""
    global latest_results
    if latest_results:
        return jsonify({
            'success': True,
            'results': latest_results,
            'summary': latest_results['summary']
        })
    else:
        return jsonify({
            'success': False,
            'message': 'No scan results available. Run a scan first.'
        }), 404

@app.route('/api/reports')
def list_reports():
    """List all saved reports"""
    reports_dir = 'reports'
    if not os.path.exists(reports_dir):
        return jsonify({'reports': []})
    
    reports = []
    for filename in os.listdir(reports_dir):
        if filename.startswith('security_report_'):
            filepath = os.path.join(reports_dir, filename)
            reports.append({
                'name': filename,
                'size': os.path.getsize(filepath),
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return jsonify({'reports': sorted(reports, key=lambda x: x['modified'], reverse=True)})

@app.route('/api/reports/<filename>')
def download_report(filename):
    """Download a specific report"""
    filepath = os.path.join('reports', filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)