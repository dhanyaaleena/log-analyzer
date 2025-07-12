from flask import Blueprint, request, jsonify, current_app
import os
from extensions import db
from models import LogFile, LogEntry
from datetime import datetime

upload_bp = Blueprint('upload', __name__)

@upload_bp.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400
    # Save file
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, file.filename)
    file.save(filepath)
    # Create LogFile record (assume user_id=1 for now)
    logfile = LogFile(filename=file.filename, user_id=1)
    db.session.add(logfile)
    db.session.commit()
    # Parse file and store entries
    parsed_entries = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(' ', 9)
            if len(parts) < 10:
                continue
            entry_data = {
                'timestamp': parts[0] + ' ' + parts[1],
                'src_ip': parts[2],
                'dest_ip': parts[3],
                'domain': parts[4],
                'action': parts[5],
                'method': parts[6],
                'status_code': parts[7],
                'user_agent': parts[8],
                'bytes': parts[9],
            }
            # Store in DB
            log_entry = LogEntry(
                logfile_id=logfile.id,
                timestamp=datetime.strptime(entry_data['timestamp'], '%Y-%m-%d %H:%M:%S'),
                raw_line=line,
                parsed_data=entry_data
            )
            db.session.add(log_entry)
            parsed_entries.append(entry_data)
    db.session.commit()
    return jsonify({
        'msg': 'File uploaded, parsed, and stored',
        'filename': file.filename,
        'logfile_id': logfile.id,
        'num_logs': len(parsed_entries),
        'logs': parsed_entries,
    })
