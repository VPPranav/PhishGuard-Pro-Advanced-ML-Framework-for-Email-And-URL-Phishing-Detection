// PhishGuard Pro - Enhanced Main JavaScript functionality

document.addEventListener("DOMContentLoaded", () => {
  // Initialize theme
  initializeTheme()

  // Initialize form interactions
  initializeFormInteractions()

  // Initialize analytics charts
  initializeAnalytics()

  // Initialize feedback forms
  initializeFeedback()

  // Initialize 3D background effects
  initialize3DBackground()

  // Initialize particle system
  initializeParticles()

  // Initialize scroll animations
  initializeScrollAnimations()

  // Initialize parallax scrolling effect
  initializeParallax()

  // Initialize enhanced loading states
  initializePageTransitions()
})

function initializeTheme() {
  const theme = localStorage.getItem("theme") || "light"
  document.documentElement.setAttribute("data-theme", theme)

  // Update theme toggle button
  const themeToggle = document.querySelector(".theme-toggle")
  if (themeToggle) {
    const themeIcon = themeToggle.querySelector(".theme-icon")
    if (themeIcon) {
      themeIcon.textContent = theme === "light" ? "🌙" : "☀️"
    }
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "light" ? "dark" : "light";

  // Apply theme
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("theme", newTheme);

  // Update theme toggle button
  const themeToggle = document.querySelector(".theme-toggle");
  if (themeToggle) {
    const themeIcon = themeToggle.querySelector(".theme-icon");
    if (themeIcon) {
      // Professional SVG icons
      const sunIcon = `
        <svg xmlns="http://www.w3.org/2000/svg" 
             width="20" height="20" viewBox="0 0 24 24" 
             fill="none" stroke="currentColor" 
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"/>
          <line x1="12" y1="1" x2="12" y2="3"/>
          <line x1="12" y1="21" x2="12" y2="23"/>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
          <line x1="1" y1="12" x2="3" y2="12"/>
          <line x1="21" y1="12" x2="23" y2="12"/>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>`;

      const moonIcon = `
        <svg xmlns="http://www.w3.org/2000/svg" 
             width="20" height="20" viewBox="0 0 24 24" 
             fill="none" stroke="currentColor" 
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3
                   7 7 0 0 0 21 12.79z"/>
        </svg>`;

      themeIcon.innerHTML = newTheme === "light" ? moonIcon : sunIcon;
    }
  }

  // Smooth transition
  document.body.style.transition = "background-color 0.3s ease, color 0.3s ease";
  setTimeout(() => {
    document.body.style.transition = "";
  }, 300);
}


function initializeFormInteractions() {
  // Mode selection functionality
  const radios = document.querySelectorAll('input[name="mode"]')
  const fieldEmail = document.getElementById("field-email")
  const fieldUrl = document.getElementById("field-url")

  function updateFields() {
    const mode = document.querySelector('input[name="mode"]:checked')
    if (!mode) return

    const modeValue = mode.value
    if (modeValue === "email") {
      if (fieldEmail) fieldEmail.classList.remove("hidden")
      if (fieldUrl) fieldUrl.classList.add("hidden")
    } else if (modeValue === "url") {
      if (fieldEmail) fieldEmail.classList.add("hidden")
      if (fieldUrl) fieldUrl.classList.remove("hidden")
    } else if (modeValue === "hybrid") {
      if (fieldEmail) fieldEmail.classList.remove("hidden")
      if (fieldUrl) fieldUrl.classList.add("hidden")
    }
  }

  if (radios.length > 0) {
    radios.forEach((r) => r.addEventListener("change", updateFields))
    updateFields()
  }

  // Enhanced form validation with real-time feedback
  const forms = document.querySelectorAll("form")
  forms.forEach((form) => {
    const requiredFields = form.querySelectorAll("[required]")

    // Real-time validation
    requiredFields.forEach((field) => {
      field.addEventListener("blur", () => validateField(field))
      field.addEventListener("input", () => clearFieldError(field))
    })

    form.addEventListener("submit", (e) => {
      let isValid = true

      requiredFields.forEach((field) => {
        if (!validateField(field)) {
          isValid = false
        }
      })

      if (!isValid) {
        e.preventDefault()
        showNotification("Please fill in all required fields correctly", "danger")
      } else {
        // Add loading state to submit button
        const submitBtn = form.querySelector('button[type="submit"]')
        if (submitBtn) {
          submitBtn.classList.add("loading")
          submitBtn.disabled = true
        }
      }
    })
  })
}

function validateField(field) {
  const value = field.value.trim()
  let isValid = true
  let errorMessage = ""

  if (!value) {
    isValid = false
    errorMessage = "This field is required"
  } else if (field.type === "email" && !isValidEmail(value)) {
    isValid = false
    errorMessage = "Please enter a valid email address"
  } else if (field.type === "url" && !isValidUrl(value)) {
    isValid = false
    errorMessage = "Please enter a valid URL"
  } else if (field.name === "message" && value.length < 10) {
    isValid = false
    errorMessage = "Message must be at least 10 characters long"
  }

  if (isValid) {
    field.classList.remove("error")
    field.classList.add("valid")
    removeFieldError(field)
  } else {
    field.classList.remove("valid")
    field.classList.add("error")
    showFieldError(field, errorMessage)
  }

  return isValid
}

function clearFieldError(field) {
  field.classList.remove("error")
  removeFieldError(field)
}

function showFieldError(field, message) {
  removeFieldError(field)
  const errorDiv = document.createElement("div")
  errorDiv.className = "field-error"
  errorDiv.textContent = message
  field.parentNode.appendChild(errorDiv)
}

function removeFieldError(field) {
  const existingError = field.parentNode.querySelector(".field-error")
  if (existingError) {
    existingError.remove()
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

function isValidUrl(url) {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

function initializeAnalytics() {
  // Animate progress bars
  const progressBars = document.querySelectorAll('[style*="width:"]')
  progressBars.forEach((bar) => {
    const width = bar.style.width
    bar.style.width = "0%"
    setTimeout(() => {
      bar.style.transition = "width 1s ease-in-out"
      bar.style.width = width
    }, 100)
  })

  // Animate stat numbers
  const statNumbers = document.querySelectorAll(".stat-number")
  statNumbers.forEach((stat) => {
    const finalValue = Number.parseInt(stat.textContent)
    if (!isNaN(finalValue)) {
      animateNumber(stat, 0, finalValue, 1000)
    }
  })

  // Initialize confidence bars animation
  const confidenceBars = document.querySelectorAll(".confidence-fill")
  confidenceBars.forEach((bar, index) => {
    setTimeout(() => {
      bar.style.transition = "width 1s ease-out"
      bar.style.width = bar.style.width || "0%"
    }, index * 100)
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

function initializeFeedback() {
  const feedbackForms = document.querySelectorAll(".feedback-form")
  feedbackForms.forEach((form) => {
    form.addEventListener("submit", (e) => {
      const feedbackType = form.querySelector('input[name="feedback_type"]:checked')
      if (!feedbackType) {
        e.preventDefault()
        showNotification("Please select whether the detection was correct or incorrect", "warning")
        return
      }

      showNotification("Thank you for your feedback!", "success")
    })
  })
}

function initialize3DBackground() {
  // Create 3D background animation using CSS transforms
  const backgroundAnimation = document.querySelector(".background-animation")
  if (!backgroundAnimation) return

  // Create floating geometric shapes
  for (let i = 0; i < 5; i++) {
    const shape = document.createElement("div")
    shape.className = "floating-shape"
    shape.style.cssText = `
      position: absolute;
      width: ${Math.random() * 100 + 50}px;
      height: ${Math.random() * 100 + 50}px;
      background: linear-gradient(45deg, rgba(37, 99, 235, 0.1), rgba(5, 150, 105, 0.1));
      border-radius: ${Math.random() > 0.5 ? "50%" : "10px"};
      left: ${Math.random() * 100}%;
      top: ${Math.random() * 100}%;
      animation: float ${Math.random() * 10 + 10}s infinite linear;
      transform-style: preserve-3d;
    `
    backgroundAnimation.appendChild(shape)
  }
}

function initializeParticles() {
  const particlesContainer = document.querySelector(".floating-particles")
  if (!particlesContainer) return

  // Create particle system
  for (let i = 0; i < 20; i++) {
    const particle = document.createElement("div")
    particle.className = "particle"
    particle.style.cssText = `
      position: absolute;
      width: 4px;
      height: 4px;
      background: rgba(37, 99, 235, 0.3);
      border-radius: 50%;
      left: ${Math.random() * 100}%;
      top: ${Math.random() * 100}%;
      animation: particle-float ${Math.random() * 20 + 20}s infinite linear;
    `
    particlesContainer.appendChild(particle)
  }
}

function initializeScrollAnimations() {
  // Intersection Observer for scroll animations
  const observerOptions = {
    threshold: 0.1,
    rootMargin: "0px 0px -50px 0px",
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("animate-in")
      }
    })
  }, observerOptions)

  // Observe all cards and major elements
  document.querySelectorAll(".card, .stat-card, .chart-card").forEach((el) => {
    el.classList.add("animate-on-scroll")
    observer.observe(el)
  })
}

function showNotification(message, type = "info") {
  // Create notification element with enhanced styling
  const notification = document.createElement("div")
  notification.className = `notification ${type}`

  const icon = getNotificationIcon(type)
  notification.innerHTML = `
    <div class="notification-content">
      <span class="notification-icon">${icon}</span>
      <span class="notification-message">${message}</span>
      <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
    </div>
  `

  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 10000;
    max-width: 400px;
    opacity: 0;
    transform: translateX(100%);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  `

  document.body.appendChild(notification)

  // Animate in
  setTimeout(() => {
    notification.style.opacity = "1"
    notification.style.transform = "translateX(0)"
  }, 10)

  // Auto remove after 5 seconds
  setTimeout(() => {
    notification.style.opacity = "0"
    notification.style.transform = "translateX(100%)"
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification)
      }
    }, 300)
  }, 5000)
}

function getNotificationIcon(type) {
  const icons = {
    success: "✅",
    danger: "❌",
    warning: "⚠️",
    info: "ℹ️",
  }
  return icons[type] || icons.info
}

// Parallax scrolling effect
function initializeParallax() {
  window.addEventListener("scroll", () => {
    const scrolled = window.pageYOffset
    const parallaxElements = document.querySelectorAll(".parallax")

    parallaxElements.forEach((element) => {
      const speed = element.dataset.speed || 0.5
      const yPos = -(scrolled * speed)
      element.style.transform = `translateY(${yPos}px)`
    })
  })
}

// Enhanced loading states
function addLoadingState(element) {
  element.classList.add("loading")
  element.disabled = true

  const originalText = element.textContent
  element.textContent = "Loading..."

  return () => {
    element.classList.remove("loading")
    element.disabled = false
    element.textContent = originalText
  }
}

// Smooth page transitions
function initializePageTransitions() {
  document.addEventListener("click", (e) => {
    const link = e.target.closest("a[href]")
    if (link && link.hostname === window.location.hostname) {
      e.preventDefault()

      document.body.classList.add("page-transition")

      setTimeout(() => {
        window.location.href = link.href
      }, 300)
    }
  })
}

// Export functions for global access
window.toggleTheme = toggleTheme
window.showNotification = showNotification
window.addLoadingState = addLoadingState
