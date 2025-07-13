// AI Cybersecurity System JavaScript

class AISecuritySystem {
  constructor() {
    this.threats = []
    this.actionLog = []
    this.stats = {
      threatsBlocked: 0,
      packetsAnalyzed: 0,
      anomaliesDetected: 0,
      systemHealth: 98.5,
      actionsToday: 0,
    }

    this.threatTypes = [
      "malware_detected",
      "phishing_attempt",
      "ddos_attack",
      "unauthorized_access",
      "suspicious_network_activity",
      "ransomware_signature",
      "data_exfiltration",
      "brute_force_attack",
    ]

    this.init()
  }

  init() {
    this.setupEventListeners()
    this.startRealTimeMonitoring()
    this.updateDisplay()
  }

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        this.switchTab(e.target.dataset.tab)
      })
    })
  }

  switchTab(tabName) {
    // Remove active class from all tabs and panes
    document.querySelectorAll(".tab-btn").forEach((btn) => btn.classList.remove("active"))
    document.querySelectorAll(".tab-pane").forEach((pane) => pane.classList.remove("active"))

    // Add active class to selected tab and pane
    document.querySelector(`[data-tab="${tabName}"]`).classList.add("active")
    document.getElementById(tabName).classList.add("active")
  }

  startRealTimeMonitoring() {
    // Simulate real-time threat detection
    setInterval(() => {
      this.simulateNetworkAnalysis()
      this.updateStats()
      this.updateDisplay()
    }, 3000)

    // Update network metrics
    setInterval(() => {
      this.updateNetworkMetrics()
    }, 5000)
  }

  simulateNetworkAnalysis() {
    // Simulate AI threat detection
    const threatDetected = Math.random() > 0.7 // 30% chance of threat

    if (threatDetected) {
      const threat = this.generateThreat()
      this.threats.unshift(threat)
      this.stats.threatsBlocked++

      // Limit threat list to 10 items
      if (this.threats.length > 10) {
        this.threats = this.threats.slice(0, 10)
      }

      // Log automated response
      this.logAutomatedAction(threat)
    }

    // Update anomaly detection
    if (Math.random() > 0.9) {
      this.stats.anomaliesDetected++
    }
  }

  generateThreat() {
    const type = this.threatTypes[Math.floor(Math.random() * this.threatTypes.length)]
    const severities = ["low", "medium", "high"]
    const severity = severities[Math.floor(Math.random() * severities.length)]
    const confidence = (Math.random() * 0.4 + 0.6) * 100 // 60-100%

    return {
      id: Date.now(),
      type: type,
      severity: severity,
      confidence: confidence.toFixed(1),
      timestamp: new Date().toLocaleTimeString(),
      status: severity === "high" ? "blocked" : "monitoring",
      source: this.generateRandomIP(),
    }
  }

  generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
  }

  logAutomatedAction(threat) {
    const actions = [
      "IP Address Blocked",
      "Traffic Filtered",
      "Alert Sent to SOC",
      "Quarantine Applied",
      "Access Denied",
      "Firewall Rule Updated",
    ]

    const action = {
      id: Date.now(),
      type: actions[Math.floor(Math.random() * actions.length)],
      threat: threat.type,
      timestamp: new Date().toLocaleTimeString(),
      status: "completed",
    }

    this.actionLog.unshift(action)
    this.stats.actionsToday++

    // Limit action log to 15 items
    if (this.actionLog.length > 15) {
      this.actionLog = this.actionLog.slice(0, 15)
    }

    this.updateActionLog()
  }

  updateStats() {
    // Simulate packet analysis
    this.stats.packetsAnalyzed += Math.floor(Math.random() * 100) + 50

    // Simulate system health fluctuation
    this.stats.systemHealth += (Math.random() - 0.5) * 2
    this.stats.systemHealth = Math.max(95, Math.min(100, this.stats.systemHealth))
  }

  updateDisplay() {
    // Update stats dashboard
    document.getElementById("threats-blocked").textContent = this.stats.threatsBlocked
    document.getElementById("packets-analyzed").textContent = this.stats.packetsAnalyzed.toLocaleString()
    document.getElementById("anomalies-detected").textContent = this.stats.anomaliesDetected
    document.getElementById("system-health").textContent = this.stats.systemHealth.toFixed(1) + "%"
    document.getElementById("actions-today").textContent = this.stats.actionsToday

    // Update threat list
    this.updateThreatList()
  }

  updateThreatList() {
    const threatList = document.getElementById("threat-list")

    if (this.threats.length === 0) {
      threatList.innerHTML = `
                <div class="no-threats">
                    <i class="fas fa-shield-check"></i>
                    <p>No threats detected. System monitoring...</p>
                </div>
            `
      return
    }

    threatList.innerHTML = this.threats
      .map(
        (threat) => `
            <div class="threat-item ${threat.severity}">
                <div class="threat-info">
                    <h4>${threat.type.replace(/_/g, " ").toUpperCase()}</h4>
                    <p>Source: ${threat.source} • Confidence: ${threat.confidence}% • ${threat.timestamp}</p>
                </div>
                <div class="threat-badges">
                    <span class="badge ${this.getSeverityBadgeClass(threat.severity)}">${threat.severity}</span>
                    <span class="badge ${this.getStatusBadgeClass(threat.status)}">${threat.status}</span>
                </div>
            </div>
        `,
      )
      .join("")
  }

  updateActionLog() {
    const actionLog = document.getElementById("action-log")

    if (this.actionLog.length === 0) {
      actionLog.innerHTML = `
                <div class="no-actions">
                    <i class="fas fa-clock"></i>
                    <p>No recent actions. System monitoring...</p>
                </div>
            `
      return
    }

    actionLog.innerHTML = this.actionLog
      .map(
        (action) => `
            <div class="action-log-item">
                <div>
                    <span class="action-type">${action.type}</span>
                    <div class="action-details">
                        <small>Target: ${action.threat.replace(/_/g, " ")}</small>
                    </div>
                </div>
                <div>
                    <span class="badge success">${action.status}</span>
                    <div class="action-time">${action.timestamp}</div>
                </div>
            </div>
        `,
      )
      .join("")
  }

  updateNetworkMetrics() {
    // Simulate network metrics
    const throughput = (Math.random() * 2 + 1.5).toFixed(1)
    const connections = Math.floor(Math.random() * 500) + 1000
    const suspiciousIPs = Math.floor(Math.random() * 5) + 1

    document.getElementById("network-throughput").textContent = throughput + " GB/s"
    document.getElementById("active-connections").textContent = connections.toLocaleString()
    document.getElementById("suspicious-ips").textContent = suspiciousIPs
  }

  getSeverityBadgeClass(severity) {
    switch (severity) {
      case "high":
        return "danger"
      case "medium":
        return "warning"
      case "low":
        return "info"
      default:
        return "info"
    }
  }

  getStatusBadgeClass(status) {
    switch (status) {
      case "blocked":
        return "danger"
      case "quarantined":
        return "warning"
      case "monitoring":
        return "info"
      case "clean":
        return "success"
      default:
        return "info"
    }
  }
}

// AI Analysis Functions
class AIAnalysis {
  static analyzeFile(file) {
    const malwareTypes = ["clean", "trojan", "ransomware", "spyware", "adware", "virus"]
    const classification = malwareTypes[Math.floor(Math.random() * malwareTypes.length)]
    const confidence = (Math.random() * 30 + 70).toFixed(1) // 70-100%
    const isMalicious = classification !== "clean"

    return {
      classification: classification,
      confidence: confidence,
      isMalicious: isMalicious,
      status: isMalicious ? "quarantined" : "clean",
    }
  }

  static analyzeNetwork(networkRange) {
    return {
      hostsFound: Math.floor(Math.random() * 50) + 10,
      openPorts: Math.floor(Math.random() * 20) + 5,
      vulnerabilities: Math.floor(Math.random() * 3),
      riskLevel: Math.random() > 0.7 ? "medium" : "low",
    }
  }

  static runBehaviorAnalysis() {
    const patterns = ["normal", "suspicious", "anomalous"]
    return {
      loginPattern: patterns[Math.floor(Math.random() * patterns.length)],
      accessFrequency: patterns[Math.floor(Math.random() * patterns.length)],
      location: patterns[Math.floor(Math.random() * patterns.length)],
      deviceFingerprint: "verified",
    }
  }
}

// Global Functions
function runDeepScan() {
  const button = event.target
  const scanResults = document.getElementById("scan-results")

  button.textContent = "Scanning..."
  button.disabled = true

  setTimeout(() => {
    const results = {
      packets: Math.floor(Math.random() * 10000) + 5000,
      threats: Math.floor(Math.random() * 5) + 1,
      anomalies: Math.floor(Math.random() * 3) + 1,
      clean: (95 + Math.random() * 4).toFixed(1),
    }

    document.getElementById("scan-packets").textContent = results.packets.toLocaleString()
    document.getElementById("scan-threats").textContent = results.threats
    document.getElementById("scan-anomalies").textContent = results.anomalies
    document.getElementById("scan-clean").textContent = results.clean + "%"

    scanResults.style.display = "block"
    button.textContent = "Run Deep Scan"
    button.disabled = false
  }, 2000)
}

function clearThreats() {
  if (window.aiSystem) {
    window.aiSystem.threats = []
    window.aiSystem.updateThreatList()
  }
}

function analyzeFile(input) {
  const file = input.files[0]
  if (!file) return

  const result = AIAnalysis.analyzeFile(file)
  const resultDiv = document.getElementById("file-analysis-result")

  document.getElementById("analyzed-filename").textContent = file.name
  document.getElementById("file-classification").textContent = result.classification
  document.getElementById("file-classification").className = `badge ${result.isMalicious ? "danger" : "success"}`
  document.getElementById("file-confidence").textContent = result.confidence + "%"
  document.getElementById("file-status").textContent = result.status
  document.getElementById("file-status").className = `badge ${result.isMalicious ? "warning" : "success"}`

  resultDiv.style.display = "block"

  // Add to threat log if malicious
  if (result.isMalicious && window.aiSystem) {
    const threat = {
      id: Date.now(),
      type: `file_analysis_${result.classification}`,
      severity: "high",
      confidence: result.confidence,
      timestamp: new Date().toLocaleTimeString(),
      status: result.status,
      source: `File: ${file.name}`,
    }

    window.aiSystem.threats.unshift(threat)
    window.aiSystem.stats.threatsBlocked++
    window.aiSystem.updateThreatList()
    window.aiSystem.logAutomatedAction(threat)
  }
}

function analyzeNetwork() {
  const networkInput = document.getElementById("network-input").value
  if (!networkInput) {
    alert("Please enter a network range or IP address")
    return
  }

  const result = AIAnalysis.analyzeNetwork(networkInput)
  const resultDiv = document.getElementById("network-analysis-result")

  document.getElementById("hosts-found").textContent = result.hostsFound
  document.getElementById("open-ports").textContent = result.openPorts
  document.getElementById("vulnerabilities").textContent = result.vulnerabilities
  document.getElementById("vulnerabilities").className = `badge ${result.vulnerabilities > 0 ? "warning" : "success"}`
  document.getElementById("risk-level").textContent = result.riskLevel
  document.getElementById("risk-level").className =
    `badge ${result.riskLevel === "high" ? "danger" : result.riskLevel === "medium" ? "warning" : "success"}`

  resultDiv.style.display = "block"
}

function runBehaviorAnalysis() {
  const result = AIAnalysis.runBehaviorAnalysis()

  // Update behavior analysis display
  const behaviorItems = document.querySelectorAll(".behavior-item")
  behaviorItems[0].querySelector(".badge").textContent = result.loginPattern
  behaviorItems[0].querySelector(".badge").className =
    `badge ${result.loginPattern === "normal" ? "success" : "warning"}`

  behaviorItems[1].querySelector(".badge").textContent = result.accessFrequency
  behaviorItems[1].querySelector(".badge").className =
    `badge ${result.accessFrequency === "normal" ? "success" : "warning"}`

  behaviorItems[2].querySelector(".badge").textContent = result.location
  behaviorItems[2].querySelector(".badge").className = `badge ${result.location === "normal" ? "success" : "warning"}`

  behaviorItems[3].querySelector(".badge").textContent = result.deviceFingerprint
  behaviorItems[3].querySelector(".badge").className = "badge info"
}

// Initialize the system when page loads
document.addEventListener("DOMContentLoaded", () => {
  window.aiSystem = new AISecuritySystem()

  // Add some initial demo data
  setTimeout(() => {
    window.aiSystem.stats.threatsBlocked = 15
    window.aiSystem.stats.packetsAnalyzed = 125000
    window.aiSystem.stats.anomaliesDetected = 3
    window.aiSystem.updateDisplay()
  }, 1000)
})
