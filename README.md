# ☁️ awsScan: The Modern AWS Dashboard & Auditor

**awsScan** is a powerful, real-time AWS resource management dashboard designed for DevOps engineers and developers who want full visibility into their infrastructure without the complexity of the AWS Console.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/docker-ready-cyan)

---

### 🔥 Key Features

- **🚀 Real-Time Discovery:** Instantly scan all AWS regions for **EC2, S3, RDS, Lambda, EBS, VPC, DynamoDB, and CloudFront**.
- **💰 Cost Intelligence:** Estimated monthly burn rate per service and per region to help you find hidden costs.
- **🛡️ Security Auditing:** Find publicly exposed resources, orphaned volumes, and insecure IAM configurations automatically.
- **⚙️ Deep Customization:**
  - **Region Filtering:** Limit scans to specific regions to speed up performance.
  - **Custom Tagging Policy:** Define your own "Required Tags" and audit your alignment instantly.
  - **Control Center:** Start, Stop, or Terminate instances directly from the dashboard.
- **📊 Interactive UI:** Dark/Light mode toggles, compact data views, and real-time status polling.
- **📥 Export Ready:** Download your full AWS inventory in **CSV or JSON** with one click.

---

### 🛠️ Tech Stack

- **Backend:** FastAPI (Python 3.10+)
- **Frontend:** Vanilla JS, CSS3, HTML5 (Modular & Responsive)
- **AWS SDK:** Boto3 (Multi-region Threading)
- **Deployment:** Docker & Gunicorn (Production Ready)

---

### 🚀 Getting Started

#### Option 1: Local Development
```bash
# Clone the repository
git clone https://github.com/skyneon1/awsScan.git
cd awsScan

# Install dependencies
pip install -r requirements.txt

# Start the dashboard
uvicorn main:app --reload --port 8000
```
Visit `http://localhost:8000` to start scanning!

#### Option 2: Docker (Recommended for Production)
```bash
docker build -t awsscan .
docker run -p 8000:8000 awsscan
```

---

### 🔐 Security & Privacy
**awsScan** is built with security in mind.
- **No Persistence:** Credentials are never stored in a database (unless configured). 
- **Direct Connection:** Your browser communicates only with your backend, which then talks directly to the AWS API.

---

### 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/skyneon1/awsScan/issues).

### 🖋️ License
Distributed under the MIT License. See `LICENSE` for more information.
