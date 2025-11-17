// Advanced Analytics Dashboard JavaScript
// Handles chart initialization, data visualization, and interactive features

// Chart instances
let timelineChart = null
let modeChart = null
let threatChart = null
let detectionRateChart = null
let confidenceChart = null
let activityChart = null
let modeTrendChart = null
let confidenceTrendChart = null


// This will be populated from the server-side data
const analyticsData = window.analyticsData || {
  emailDetections: 0,
  urlDetections: 0,
  hybridDetections: 0,
  totalDetections: 0,
  phishingCount: 0,
  safeCount: 0,
  detections: [],
}

// Utility function to show notifications
function showNotification(message, type) {
  if (typeof window.showNotification === "function") {
    window.showNotification(message, type)
  } else {
    console.log(`Notification (${type}): ${message}`)
  }
}

function initializeChartDefaults() {
  if (typeof window.Chart !== "undefined") {
    window.Chart.defaults.font.family = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    window.Chart.defaults.font.size = 12
    window.Chart.defaults.color =
      getComputedStyle(document.documentElement).getPropertyValue("--text-secondary").trim() || "#6b7280"
  }
}

function initializeAnalyticsCharts() {
  if (typeof window.Chart === "undefined") {
    const script = document.createElement("script")
    script.src = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.min.js"
    script.onload = () => {
      initializeChartDefaults()
      initializeTimelineChart()
      initializeModeChart()
      initializeThreatChart()
      initializeDetectionRateChart()
      initializeAdvancedCharts()
    }
    document.head.appendChild(script)
  } else {
    initializeChartDefaults()
    initializeTimelineChart()
    initializeModeChart()
    initializeThreatChart()
    initializeDetectionRateChart()
    initializeAdvancedCharts()
  }
}

function initializeTimelineChart() {
  const ctx = document.getElementById("timelineChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const timelineData = generateTimelineData(30)

  timelineChart = new window.Chart(ctx, {
    type: "line",
    data: {
      labels: timelineData.labels,
      datasets: [
        {
          label: "Total Detections",
          data: timelineData.total,
          borderColor: "rgb(37, 99, 235)",
          backgroundColor: "rgba(37, 99, 235, 0.1)",
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointRadius: 6,
          pointHoverRadius: 8,
          pointBackgroundColor: "rgb(37, 99, 235)",
          pointBorderColor: "#ffffff",
          pointBorderWidth: 2,
        },
        {
          label: "Phishing Detected",
          data: timelineData.phishing,
          borderColor: "rgb(220, 38, 38)",
          backgroundColor: "rgba(220, 38, 38, 0.1)",
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointRadius: 6,
          pointHoverRadius: 8,
          pointBackgroundColor: "rgb(220, 38, 38)",
          pointBorderColor: "#ffffff",
          pointBorderWidth: 2,
        },
        {
          label: "Safe Content",
          data: timelineData.safe,
          borderColor: "rgb(5, 150, 105)",
          backgroundColor: "rgba(5, 150, 105, 0.1)",
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointRadius: 6,
          pointHoverRadius: 8,
          pointBackgroundColor: "rgb(5, 150, 105)",
          pointBorderColor: "#ffffff",
          pointBorderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        intersect: false,
        mode: "index",
      },
      plugins: {
        legend: {
          position: "top",
          labels: {
            usePointStyle: true,
            padding: 20,
            font: {
              size: 13,
              weight: "500",
            },
          },
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          borderColor: "rgba(255, 255, 255, 0.1)",
          borderWidth: 1,
          cornerRadius: 8,
          displayColors: true,
          callbacks: {
            title: (context) => `Date: ${context[0].label}`,
            label: (context) => `${context.dataset.label}: ${context.parsed.y} detections`,
          },
        },
      },
      scales: {
        x: {
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
            drawBorder: false,
          },
          ticks: {
            font: {
              size: 11,
            },
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
            drawBorder: false,
          },
          ticks: {
            font: {
              size: 11,
            },
            callback: (value) => Math.floor(value),
          },
        },
      },
      elements: {
        point: {
          hoverBorderWidth: 3,
        },
      },
    },
  })
}

function initializeModeChart() {
  const ctx = document.getElementById("modeChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const data = {
    labels: ["Email Analysis", "URL Analysis", "Hybrid Analysis"],
    datasets: [
      {
        data: [analyticsData.emailDetections, analyticsData.urlDetections, analyticsData.hybridDetections],
        backgroundColor: ["rgba(37, 99, 235, 0.8)", "rgba(5, 150, 105, 0.8)", "rgba(217, 119, 6, 0.8)"],
        borderColor: ["rgb(37, 99, 235)", "rgb(5, 150, 105)", "rgb(217, 119, 6)"],
        borderWidth: 2,
        hoverOffset: 10,
      },
    ],
  }

  modeChart = new window.Chart(ctx, {
    type: "doughnut",
    data: data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "60%",
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          borderColor: "rgba(255, 255, 255, 0.1)",
          borderWidth: 1,
          cornerRadius: 8,
          callbacks: {
            label: (context) => {
              const total = context.dataset.data.reduce((a, b) => a + b, 0)
              const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : "0"
              return `${context.label}: ${context.parsed} (${percentage}%)`
            },
          },
        },
      },
      animation: {
        animateRotate: true,
        duration: 2000,
        easing: "easeOutQuart",
      },
    },
  })
}

function initializeThreatChart() {
  const ctx = document.getElementById("threatChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const data = {
    labels: ["Safe Content", "Phishing Detected"],
    datasets: [
      {
        data: [analyticsData.safeCount, analyticsData.phishingCount],
        backgroundColor: ["rgba(5, 150, 105, 0.8)", "rgba(220, 38, 38, 0.8)"],
        borderColor: ["rgb(5, 150, 105)", "rgb(220, 38, 38)"],
        borderWidth: 2,
        hoverOffset: 8,
      },
    ],
  }

  threatChart = new window.Chart(ctx, {
    type: "pie",
    data: data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          borderColor: "rgba(255, 255, 255, 0.1)",
          borderWidth: 1,
          cornerRadius: 8,
          callbacks: {
            label: (context) => {
              const total = context.dataset.data.reduce((a, b) => a + b, 0)
              const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : "0"
              return `${context.label}: ${context.parsed} (${percentage}%)`
            },
          },
        },
      },
      animation: {
        animateRotate: true,
        duration: 2000,
        easing: "easeOutQuart",
      },
    },
  })
}

function initializeDetectionRateChart() {
  const ctx = document.getElementById("detectionRateChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const data = {
    labels: ["Email", "URL", "Hybrid"],
    datasets: [
      {
        label: "Safe Detections",
        data: [
          Math.floor(analyticsData.emailDetections * 0.7),
          Math.floor(analyticsData.urlDetections * 0.8),
          Math.floor(analyticsData.hybridDetections * 0.75),
        ],
        backgroundColor: "rgba(5, 150, 105, 0.8)",
        borderColor: "rgb(5, 150, 105)",
        borderWidth: 1,
      },
      {
        label: "Phishing Detections",
        data: [
          Math.floor(analyticsData.emailDetections * 0.3),
          Math.floor(analyticsData.urlDetections * 0.2),
          Math.floor(analyticsData.hybridDetections * 0.25),
        ],
        backgroundColor: "rgba(220, 38, 38, 0.8)",
        borderColor: "rgb(220, 38, 38)",
        borderWidth: 1,
      },
    ],
  }

  detectionRateChart = new window.Chart(ctx, {
    type: "bar",
    data: data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "top",
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          borderColor: "rgba(255, 255, 255, 0.1)",
          borderWidth: 1,
          cornerRadius: 8,
        },
      },
      scales: {
        x: {
          stacked: true,
          grid: {
            display: false,
          },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
          },
        },
      },
    },
  })
}

function generateTimelineData(days = 30) {
  const labels = []
  const total = []
  const phishing = []
  const safe = []

  for (let i = days - 1; i >= 0; i--) {
    const date = new Date()
    date.setDate(date.getDate() - i)
    labels.push(date.toLocaleDateString("en-US", { month: "short", day: "numeric" }))

    // Generate realistic data based on actual analytics
    const dailyTotal = Math.floor(Math.random() * 15) + 2
    const phishingRate =
      analyticsData.totalDetections > 0 ? analyticsData.phishingCount / analyticsData.totalDetections : 0.25
    const dailyPhishing = Math.floor(dailyTotal * phishingRate)
    const dailySafe = dailyTotal - dailyPhishing

    total.push(dailyTotal)
    phishing.push(dailyPhishing)
    safe.push(dailySafe)
  }

  return { labels, total, phishing, safe }
}

function updateTimelineChart(days) {
  if (!timelineChart) return

  const timelineData = generateTimelineData(Number.parseInt(days))
  timelineChart.data.labels = timelineData.labels
  timelineChart.data.datasets[0].data = timelineData.total
  timelineChart.data.datasets[1].data = timelineData.phishing
  timelineChart.data.datasets[2].data = timelineData.safe
  timelineChart.update("active")
}

function animateStatNumbers() {
  const statNumbers = document.querySelectorAll(".stat-number[data-count]")

  statNumbers.forEach((stat) => {
    const finalValue = Number.parseInt(stat.getAttribute("data-count"))
    if (isNaN(finalValue)) return

    animateNumber(stat, 0, finalValue, 2000)
  })
}

function initializeModeTrendChart() {
  const ctx = document.getElementById("modeTrendChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const labels = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

  modeTrendChart = new window.Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Email",
          data: labels.map(() => Math.floor(Math.random() * 20)),
          borderColor: "rgb(37, 99, 235)",
          backgroundColor: "rgba(37, 99, 235, 0.1)",
          fill: true,
          tension: 0.4,
        },
        {
          label: "URL",
          data: labels.map(() => Math.floor(Math.random() * 15)),
          borderColor: "rgb(5, 150, 105)",
          backgroundColor: "rgba(5, 150, 105, 0.1)",
          fill: true,
          tension: 0.4,
        },
        {
          label: "Hybrid",
          data: labels.map(() => Math.floor(Math.random() * 10)),
          borderColor: "rgb(217, 119, 6)",
          backgroundColor: "rgba(217, 119, 6, 0.1)",
          fill: true,
          tension: 0.4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "top" },
        tooltip: {
          backgroundColor: "rgba(0,0,0,0.8)",
          titleColor: "#fff",
          bodyColor: "#fff",
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { stepSize: 5 }
        }
      }
    },
  })
}

function initializeConfidenceTrendChart() {
  const ctx = document.getElementById("confidenceTrendChart")
  if (!ctx || typeof window.Chart === "undefined") return

  const labels = Array.from({ length: 14 }, (_, i) => `Day ${i+1}`)

  confidenceTrendChart = new window.Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Avg Confidence",
          data: labels.map(() => (Math.random() * 100).toFixed(1)),
          borderColor: "rgb(99, 102, 241)",
          backgroundColor: "rgba(99, 102, 241, 0.1)",
          fill: true,
          tension: 0.3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(0,0,0,0.8)",
          titleColor: "#fff",
          bodyColor: "#fff",
          callbacks: {
            label: (context) => `Confidence: ${context.parsed.y}%`
          }
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 100,
          ticks: { callback: (v) => v + "%" }
        }
      }
    },
  })
}


function animateNumber(element, start, end, duration) {
  const startTime = performance.now()

  function update(currentTime) {
    const elapsed = currentTime - startTime
    const progress = Math.min(elapsed / duration, 1)

    // Easing function for smooth animation
    const easeOutQuart = 1 - Math.pow(1 - progress, 4)
    const current = Math.floor(start + (end - start) * easeOutQuart)

    element.textContent = current.toLocaleString()

    if (progress < 1) {
      requestAnimationFrame(update)
    }
  }

  requestAnimationFrame(update)
}

// Table filtering and search functionality
function filterTable(searchTerm) {
  const table = document.getElementById("detectionsTable")
  if (!table) return

  const rows = table.getElementsByTagName("tbody")[0].getElementsByTagName("tr")
  const term = searchTerm.toLowerCase()

  Array.from(rows).forEach((row) => {
    const text = row.textContent.toLowerCase()
    row.style.display = text.includes(term) ? "" : "none"
  })
}

function filterContactsTable(searchTerm) {
  const table = document.getElementById("contactsTable")
  if (!table) return

  const rows = table.getElementsByTagName("tbody")[0].getElementsByTagName("tr")
  const term = searchTerm.toLowerCase()

  Array.from(rows).forEach((row) => {
    const text = row.textContent.toLowerCase()
    row.style.display = text.includes(term) ? "" : "none"
  })
}

function filterFeedbackTable(searchTerm) {
  const table = document.getElementById("feedbackTable")
  if (!table) return

  const rows = table.getElementsByTagName("tbody")[0].getElementsByTagName("tr")
  const term = searchTerm.toLowerCase()

  Array.from(rows).forEach((row) => {
    const text = row.textContent.toLowerCase()
    row.style.display = text.includes(term) ? "" : "none"
  })
}

function filterDetectionsTable(searchTerm) {
  const table = document.getElementById("systemDetectionsTable")
  if (!table) return

  const rows = table.getElementsByTagName("tbody")[0].getElementsByTagName("tr")
  const term = searchTerm.toLowerCase()

  Array.from(rows).forEach((row) => {
    const text = row.textContent.toLowerCase()
    row.style.display = text.includes(term) ? "" : "none"
  })
}

// Admin tab switching
function switchTab(tabName) {
  // Hide all tab contents
  const tabContents = document.querySelectorAll(".tab-content")
  tabContents.forEach((content) => content.classList.remove("active"))

  // Remove active class from all tab buttons
  const tabButtons = document.querySelectorAll(".tab-button")
  tabButtons.forEach((button) => button.classList.remove("active"))

  // Show selected tab content
  const selectedTab = document.getElementById(`${tabName}-tab`)
  if (selectedTab) {
    selectedTab.classList.add("active")
  }

  // Add active class to clicked button
  const clickedButton = event.target.closest(".tab-button")
  if (clickedButton) {
    clickedButton.classList.add("active")
  }
}

// Export functionality
function exportAnalytics() {
  showNotification("Analytics export feature coming soon!", "info")
}

function exportTableData() {
  showNotification("Table export feature coming soon!", "info")
}

function exportSystemReport() {
  showNotification("System report export feature coming soon!", "info")
}

// Refresh functionality
function refreshAnalytics() {
  showNotification("Refreshing analytics data...", "info")
  setTimeout(() => {
    location.reload()
  }, 1000)
}

function refreshSystemData() {
  showNotification("Refreshing system data...", "info")
  setTimeout(() => {
    location.reload()
  }, 1000)
}

// Modal and detail view functions
function viewDetails(detectionId) {
  showNotification("Detail view feature coming soon!", "info")
}

function viewContact(contactId) {
  showNotification("Contact detail view feature coming soon!", "info")
}

function viewFeedback(feedbackId) {
  showNotification("Feedback detail view feature coming soon!", "info")
}

function viewSystemDetection(detectionId) {
  showNotification("System detection detail view feature coming soon!", "info")
}

function replyContact(email) {
  window.location.href = `mailto:${email}`
}

// Utility functions
function formatDate(dateString) {
  const date = new Date(dateString)
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

function formatPercentage(value, total) {
  if (total === 0) return "0%"
  return ((value / total) * 100).toFixed(1) + "%"
}

// Advanced chart functions
function initializeAdvancedCharts() {
  initializeConfidenceChart()
  initializeActivityHeatmap()
  initializeModeTrendChart()
  initializeConfidenceTrendChart()
}


function initializeConfidenceChart() {
  const ctx = document.getElementById("confidenceChart")
  if (!ctx || typeof window.Chart === "undefined") return

  // Generate confidence distribution data
  const confidenceRanges = ["0-20%", "20-40%", "40-60%", "60-80%", "80-100%"]
  const confidenceData = [2, 5, 8, 15, 25] // Sample data

  confidenceChart = new window.Chart(ctx, {
    type: "bar",
    data: {
      labels: confidenceRanges,
      datasets: [
        {
          label: "Detection Count",
          data: confidenceData,
          backgroundColor: [
            "rgba(220, 38, 38, 0.8)",
            "rgba(217, 119, 6, 0.8)",
            "rgba(234, 179, 8, 0.8)",
            "rgba(34, 197, 94, 0.8)",
            "rgba(37, 99, 235, 0.8)",
          ],
          borderColor: [
            "rgb(220, 38, 38)",
            "rgb(217, 119, 6)",
            "rgb(234, 179, 8)",
            "rgb(34, 197, 94)",
            "rgb(37, 99, 235)",
          ],
          borderWidth: 2,
          borderRadius: 8,
          borderSkipped: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          borderColor: "rgba(255, 255, 255, 0.1)",
          borderWidth: 1,
          cornerRadius: 8,
        },
      },
      scales: {
        x: {
          grid: {
            display: false,
          },
          ticks: {
            font: {
              size: 11,
            },
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
          },
          ticks: {
            font: {
              size: 11,
            },
          },
        },
      },
    },
  })
}

function initializeActivityHeatmap() {
  const ctx = document.getElementById("activityHeatmap")
  if (!ctx || typeof window.Chart === "undefined") return

  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
  const hours = Array.from({ length: 24 }, (_, i) => i)

  const heatmapData = []
  days.forEach((day, dayIndex) => {
    hours.forEach((hour) => {
      heatmapData.push({
        x: hour,
        y: dayIndex,
        v: Math.floor(Math.random() * 10), // Random activity level
      })
    })
  })

  activityChart = new window.Chart(ctx, {
    type: "scatter",
    data: {
      datasets: [
        {
          label: "Activity Level",
          data: heatmapData,
          backgroundColor: (context) => {
            const value = context.raw.v
            const alpha = value / 10
            return `rgba(37, 99, 235, ${alpha})`
          },
          pointRadius: (context) => Math.max(2, context.raw.v),
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#ffffff",
          bodyColor: "#ffffff",
          callbacks: {
            title: (context) => {
              const point = context[0].raw
              return `${days[point.y]} ${point.x}:00`
            },
            label: (context) => `Activity: ${context.raw.v}/10`,
          },
        },
      },
      scales: {
        x: {
          type: "linear",
          position: "bottom",
          min: 0,
          max: 23,
          ticks: {
            stepSize: 2,
            callback: (value) => value + ":00",
          },
          title: { display: true, text: "Hour of Day" },
        },
        y: {
          type: "linear",
          min: -0.5,
          max: 6.5,
          ticks: {
            stepSize: 1,
            callback: (value) => days[Math.round(value)] || "",
          },
          title: { display: true, text: "Day of Week" },
        },
      },
    },
  })
}


// Initialize analytics when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Add smooth scrolling to all anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault()
      const target = document.querySelector(this.getAttribute("href"))
      if (target) {
        target.scrollIntoView({
          behavior: "smooth",
          block: "start",
        })
      }
    })
  })

  // Add loading states to buttons
  document.querySelectorAll(".btn").forEach((button) => {
    button.addEventListener("click", function () {
      if (!this.classList.contains("loading")) {
        this.classList.add("loading")
        setTimeout(() => {
          this.classList.remove("loading")
        }, 2000)
      }
    })
  })

  initializeChartDefaults()
initializeTimelineChart()
initializeModeChart()
initializeThreatChart()
initializeDetectionRateChart()
initializeConfidenceChart()
initializeActivityHeatmap()
animateStatNumbers()

})
