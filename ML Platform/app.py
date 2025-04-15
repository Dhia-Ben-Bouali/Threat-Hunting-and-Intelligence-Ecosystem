from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import csv
import sqlite3
from NSLKDDModel import predictLine
from PhshingEmailModel import predict_phishing
from database import init_db

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
init_db()


@app.route('/')
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin' and password == 'admin':
        return redirect(url_for('home'))
    else:
        error = "Invalid credentials, please try again."
        return render_template('login.html', error=error)  


@app.route('/home')
def home():
    import sqlite3
    from collections import defaultdict
    from datetime import datetime, timedelta

    # --- Get total phishing count ---
    conn1 = sqlite3.connect('requests.db')
    cursor1 = conn1.cursor()
    cursor1.execute("SELECT COUNT(*) FROM email_requests WHERE result = 'phishing'")
    phishing_count = cursor1.fetchone()[0]

    # --- Phishing alerts per day ---
    cursor1.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) 
        FROM email_requests 
        WHERE result = 'phishing' 
        GROUP BY DATE(timestamp) 
        ORDER BY DATE(timestamp) DESC 
        LIMIT 7
    """)
    phishing_data = cursor1.fetchall()
    conn1.close()

    # --- Get total intrusion count ---
    conn2 = sqlite3.connect('requests.db')
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT COUNT(*) FROM intrusion_detection WHERE result = 'anomaly'")
    intrusion_count = cursor2.fetchone()[0]

    # --- Intrusion alerts per day ---
    cursor2.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) 
        FROM intrusion_detection 
        WHERE result = 'anomaly' 
        GROUP BY DATE(timestamp) 
        ORDER BY DATE(timestamp) DESC 
        LIMIT 7
    """)
    intrusion_data = cursor2.fetchall()
    conn2.close()

    # --- Total alerts ---
    total_alerts = phishing_count + intrusion_count

    # --- Normalize time series data ---
    today = datetime.today().date()
    labels = [(today - timedelta(days=i)).isoformat() for i in reversed(range(7))]

    phishing_counts = defaultdict(int, {d: c for d, c in phishing_data})
    intrusion_counts = defaultdict(int, {d: c for d, c in intrusion_data})

    phishing_values = [phishing_counts[d] for d in labels]
    intrusion_values = [intrusion_counts[d] for d in labels]

    return render_template('home.html',
                           phishing_count=phishing_count,
                           intrusion_count=intrusion_count,
                           total_alerts=total_alerts,
                           labels=labels,
                           phishing_values=phishing_values,
                           intrusion_values=intrusion_values)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/Phishing')
def phishing():
    email = request.args.get('email')
    sender = request.args.get('sender')
    receiver = request.args.get('receiver')

    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    result = None
    request_id = None
    alerts = []

    if email:
        # Insert email, sender, receiver into the table
        cursor.execute(
            'INSERT INTO email_requests (email, sender, receiver) VALUES (?, ?, ?)',
            (email, sender, receiver)
        )
        request_id = cursor.lastrowid
        conn.commit()

        prediction = predict_phishing(email)  # Make sure this function exists
        result = 'phishing' if prediction == 1 else 'safe'

        # Update the result in the database
        cursor.execute('UPDATE email_requests SET result = ? WHERE id = ?', (result, request_id))
        conn.commit()

    # Now fetch email, sender, receiver, timestamp, result
    cursor.execute('SELECT email, sender, receiver, timestamp, result FROM email_requests ORDER BY timestamp DESC')
    alerts = cursor.fetchall()  # List of tuples

    conn.close()

    return render_template('phishing.html', email=email, sender=sender, receiver=receiver, result=result, alerts=alerts)


@app.route('/phishing_api' , methods=['POST'])
def phishing_api():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'No email provided'}), 400
    sender = request.args.get('sender')
    receiver = request.args.get('receiver')
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    result = None
    request_id = None
  
    
    cursor.execute(
        'INSERT INTO email_requests (email, sender, receiver) VALUES (?, ?, ?)',
        (email, sender, receiver)
    )
    request_id = cursor.lastrowid
    conn.commit()

    prediction = predict_phishing(email)  # Make sure this function exists
    result = 'phishing' if prediction == 1 else 'safe'

    # Update the result in the database
    cursor.execute('UPDATE email_requests SET result = ? WHERE id = ?', (result, request_id))
    conn.commit()
    conn.close()
    if prediction == 1:
        return jsonify({'status': 'phishing'}), 200
    else:
        return jsonify({'status': 'safe'}), 200 


@app.route('/Traffic')
def traffic():
    # Get parameters from the GET request
    protocol_type = request.args.get('protocol_type')
    service = request.args.get('service')
    flag = request.args.get('flag')
    src_bytes = request.args.get('src_bytes', type=int)
    dst_bytes = request.args.get('dst_bytes', type=int)
    duration = request.args.get('duration', type=int)
    land = request.args.get('land', type=int)
    wrong_fragment = request.args.get('wrong_fragment', type=int)
    urgent = request.args.get('urgent', type=int)

    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    result = None
    request_id = None
    alerts = []

    if protocol_type and service and flag:
        # Insert traffic values into the DB
        cursor.execute('''
            INSERT INTO intrusion_detection (
                protocol_type, service, flag, src_bytes, dst_bytes,
                duration, land, wrong_fragment, urgent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            protocol_type, service, flag, src_bytes, dst_bytes,
            duration, land, wrong_fragment, urgent
        ))

        request_id = cursor.lastrowid
        conn.commit()

        # Use your existing predictLine function for single record prediction
        result_obj = predictLine(
            protocol_type, service, duration, flag,
            src_bytes, dst_bytes, land, wrong_fragment, urgent
        )
        result = result_obj['prediction']  # 'normal' or 'anomaly'

        # Update the result in the database
        cursor.execute('UPDATE intrusion_detection SET result = ? WHERE id = ?', (result, request_id))
        conn.commit()

    # Fetch logs
    cursor.execute('''
        SELECT protocol_type, service, flag, src_bytes, dst_bytes,
               duration, land, wrong_fragment, urgent, result, timestamp
        FROM intrusion_detection
        ORDER BY timestamp DESC
    ''')
    alerts = cursor.fetchall()

    conn.close()

    return render_template(
        'traffic.html',
        result=result,
        alerts=alerts
    )


# traffic model route
@app.route('/predict_csv', methods=['GET'])
def predict_csv():
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()
    result = None
    request_id = None
    if 'file' not in request.files:
        return 'No file part in the request', 400

    file = request.files['file']

    if file.filename == '':
        return 'No selected file', 400

    # Optional: create a directory to store uploads
    upload_dir = 'uploads'
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)

    
    anomalies = []

    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Skip header

        for row in reader:
            # Assign each value to a named variable
            protocol        = row[0]
            service         = row[1]
            duration        = row[2]
            flag            = row[3]
            src_bytes       = row[4]
            dst_bytes       = row[5]
            land            = row[6]
            wrong_fragment  = row[7]
            urgent          = row[8]
            cursor.execute('''
            INSERT INTO intrusion_detection (
                protocol_type, service, flag, src_bytes, dst_bytes,
                duration, land, wrong_fragment, urgent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            protocol, service, flag, src_bytes, dst_bytes,
            duration, land, wrong_fragment, urgent
        ))
            request_id = cursor.lastrowid
            conn.commit()
            result = predictLine(
                protocol, service, duration, flag,
                src_bytes, dst_bytes, land, wrong_fragment, urgent
            )
            cursor.execute('UPDATE intrusion_detection SET result = ? WHERE id = ?', (result['prediction'], request_id))
            conn.commit()
            if result['prediction'] == 'anomaly':
                anomalies.append(result)

    # Clean up the uploaded file after processing
    os.remove(file_path)
    if anomalies:
        return jsonify({'status': 'anomaly','anomalies': anomalies})
    else:
        return jsonify({'status': 'normal'})

@app.route('/email_logs')
def view_email_logs():
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()
    cursor.execute('SELECT email, result, sender, receiver, timestamp FROM email_requests ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    conn.close()
    return render_template('email_logs.html', logs=logs)

#-----------------------------------------------------------------------------------------------

@app.route('/ManualPhishing')
def Manualphishing():
    email = request.args.get('email')
    sender = request.args.get('sender')
    receiver = request.args.get('receiver')

    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    result = None
    request_id = None
    alerts = []

    if email:
        # Insert email, sender, receiver into the table
        cursor.execute(
            'INSERT INTO email_requests (email, sender, receiver) VALUES (?, ?, ?)',
            (email, sender, receiver)
        )
        request_id = cursor.lastrowid
        conn.commit()

    # Now fetch email, sender, receiver, timestamp, result
    cursor.execute('SELECT email, sender, receiver, timestamp, result FROM email_requests ORDER BY timestamp DESC')
    alerts = cursor.fetchall()  # List of tuples

    conn.close()

    return render_template('ManualPhishing.html', email=email, sender=sender, receiver=receiver, result=result, alerts=alerts)



@app.route('/run_phishing_scan', methods=['POST'])
def run_phishing_scan():
    data = request.get_json()  # Get the data sent in the request body
    email = data.get('email')
    sender = data.get('sender')
    receiver = data.get('receiver')

    # Connect to the database to update the result
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    # Run the phishing prediction model
    prediction = predict_phishing(email)  # Use your actual phishing detection model
    result = 'phishing' if prediction == 1 else 'safe'

    # Find the email's record by its sender, receiver, and email, then update the result
    cursor.execute(
        'UPDATE email_requests SET result = ? WHERE email = ? AND sender = ? AND receiver = ?',
        (result, email, sender, receiver)
    )
    conn.commit()

    # Close the database connection
    conn.close()

    # Return the result as JSON to update the frontend dynamically
    return jsonify({"result": result})

#--------------------------------------------------------------------------------------------------------
@app.route('/ManualTraffic', methods=['GET'])
def manualtraffic():
    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()
    if 'file' not in request.files:
        cursor.execute('''
            SELECT protocol_type, service, flag, src_bytes, dst_bytes,
                   duration, land, wrong_fragment, urgent, result, timestamp
            FROM intrusion_detection
            ORDER BY timestamp DESC
        ''')
        alerts = cursor.fetchall()
        return render_template(
        'ManualTraffic.html',
        alerts=alerts,
        )

    file = request.files['file']

    if file.filename == '':
        return 'No selected file', 400

    # Optional: create a directory to store uploads
    upload_dir = 'uploads'
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)

    
    anomalies = []

    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Skip header

        for row in reader:
            # Assign each value to a named variable
            protocol        = row[0]
            service         = row[1]
            duration        = row[2]
            flag            = row[3]
            src_bytes       = row[4]
            dst_bytes       = row[5]
            land            = row[6]
            wrong_fragment  = row[7]
            urgent          = row[8]
            cursor.execute('''
            INSERT INTO intrusion_detection (
                protocol_type, service, flag, src_bytes, dst_bytes,
                duration, land, wrong_fragment, urgent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            protocol, service, flag, src_bytes, dst_bytes,
            duration, land, wrong_fragment, urgent
        ))
        conn.commit()

        # Fetch recent alerts
        cursor.execute('''
            SELECT protocol_type, service, flag, src_bytes, dst_bytes,
                   duration, land, wrong_fragment, urgent, result, timestamp
            FROM intrusion_detection
            ORDER BY timestamp DESC
        ''')
        alerts = cursor.fetchall()
        conn.close()

    return render_template(
        'ManualTraffic.html',
        alerts=alerts,
    )

@app.route('/run_model_for_alert', methods=['GET'])
def run_model_for_alert():
    src_bytes = request.args.get('src_bytes')
    dst_bytes = request.args.get('dst_bytes')
    duration = request.args.get('duration')

    print(f"[INFO] Received src={src_bytes}, dst={dst_bytes}, duration={duration}")

    if not (src_bytes and dst_bytes and duration):
        return jsonify({'error': 'Missing parameters'}), 400

    conn = sqlite3.connect('requests.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT protocol_type, service, duration, flag, src_bytes, dst_bytes,
               land, wrong_fragment, urgent, id
        FROM intrusion_detection
        WHERE src_bytes = ? AND dst_bytes = ? AND duration = ?
    ''', (src_bytes, dst_bytes, duration))
    row = cursor.fetchone()

    if not row:
        return jsonify({'error': 'No entry found'}), 404

    (
        protocol, service, duration, flag, src_bytes,
        dst_bytes, land, wrong_fragment, urgent, record_id
    ) = row

    result_obj = predictLine(
            protocol, service, duration, flag,
            src_bytes, dst_bytes, land, wrong_fragment, urgent
        )
    
    result = result_obj['prediction']  # 'normal' or 'anomal

    cursor.execute('''
        UPDATE intrusion_detection SET result = ?
         WHERE src_bytes = ? AND dst_bytes = ? AND duration = ?
    ''', (src_bytes, dst_bytes, duration))
    conn.commit()
    conn.close()

    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)

