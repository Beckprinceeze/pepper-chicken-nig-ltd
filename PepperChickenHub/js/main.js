/**
 * Pepper Chicken - Nigerian Restaurant Website
 * Main JavaScript File
 * 
 * This file contains the main functionality for the website
 * including navigation, animations, and general UI interactions.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the website
    initNavigation();
    initAnimations();
    loadFontAwesome();
    handleContactForm();
    initHeroSlideshow();
});

/**
 * Load Font Awesome icons
 */
function loadFontAwesome() {
    const script = document.createElement('script');
    script.src = 'https://kit.fontawesome.com/a076d05399.js';
    script.crossOrigin = 'anonymous';
    document.head.appendChild(script);
}

/**
 * Initialize the navigation menu
 */
function initNavigation() {
    // Get navigation elements
    const header = document.querySelector('.header');
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    const navLinks = document.querySelectorAll('.nav-link');
    
    // Add event listener for hamburger menu
    if (hamburger) {
        hamburger.addEventListener('click', function() {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });
    }
    
    // Close menu when nav link is clicked
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            hamburger.classList.remove('active');
            navMenu.classList.remove('active');
        });
    });
    
    // Add active class to current page link
    const currentPage = window.location.pathname;
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('active');
        }
    });
    
    // Change header background on scroll
    window.addEventListener('scroll', function() {
        if (window.scrollY > 100) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    });
    
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                window.scrollTo({
                    top: target.offsetTop - 80,
                    behavior: 'smooth'
                });
            }
        });
    });
}

/**
 * Initialize animations
 */
function initAnimations() {
    // Animate elements when they come into view
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animated');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1
    });
    
    animateElements.forEach(element => {
        observer.observe(element);
    });
    
    // Add animation classes based on data attributes
    animateElements.forEach(element => {
        const animation = element.dataset.animation || 'fadeIn';
        element.classList.add(animation);
    });
}

/**
 * Handle contact form submission
 */
function handleContactForm() {
    const contactForm = document.getElementById('contactForm');
    
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const subject = document.getElementById('subject').value;
            const message = document.getElementById('message').value;
            
            // Simple validation
            if (!name || !email || !message) {
                alert('Please fill in all required fields.');
                return;
            }
            
            // Show success message - in a real application, this would send the form data to a server
            const formContainer = document.querySelector('.contact-form');
            formContainer.innerHTML = `
                <div class="success-message">
                    <i class="fas fa-check-circle" style="font-size: 3rem; color: var(--green-dark); margin-bottom: 1rem;"></i>
                    <h3>Thank You!</h3>
                    <p>Your message has been sent successfully. We'll get back to you soon!</p>
                    <button class="btn mt-3" onclick="location.reload()">Send Another Message</button>
                </div>
            `;
        });
    }
}

/**
 * Initialize hero slideshow on the home page
 */
function initHeroSlideshow() {
    const slides = document.querySelectorAll('.hero-slide');
    const indicators = document.querySelectorAll('.slide-indicator');
    const prevBtn = document.querySelector('.prev-slide');
    const nextBtn = document.querySelector('.next-slide');
    
    if (!slides.length) return; // Exit if no slides found (not on home page)
    
    let currentIndex = 0;
    let slideInterval;
    
    // Function to show a specific slide
    function showSlide(index) {
        // Hide all slides
        slides.forEach(slide => {
            slide.classList.remove('active');
        });
        
        // Remove active class from all indicators
        indicators.forEach(indicator => {
            indicator.classList.remove('active');
        });
        
        // Show current slide and indicator
        currentIndex = (index + slides.length) % slides.length;
        slides[currentIndex].classList.add('active');
        indicators[currentIndex].classList.add('active');
    }
    
    // Function to advance to the next slide
    function nextSlide() {
        showSlide(currentIndex + 1);
    }
    
    // Function to go back to the previous slide
    function prevSlide() {
        showSlide(currentIndex - 1);
    }
    
    // Start automatic slideshow
    function startSlideshow() {
        stopSlideshow(); // Clear any existing interval
        slideInterval = setInterval(nextSlide, 5000); // Change slide every 5 seconds
    }
    
    // Stop automatic slideshow
    function stopSlideshow() {
        if (slideInterval) {
            clearInterval(slideInterval);
        }
    }
    
    // Add click event listeners to buttons
    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            prevSlide();
            startSlideshow(); // Restart timer after manual navigation
        });
    }
    
    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            nextSlide();
            startSlideshow(); // Restart timer after manual navigation
        });
    }
    
    // Add click event listeners to indicators
    indicators.forEach((indicator, index) => {
        indicator.addEventListener('click', () => {
            showSlide(index);
            startSlideshow(); // Restart timer after manual navigation
        });
    });
    
    // Pause slideshow on hover
    const slideshow = document.querySelector('.hero-slideshow');
    if (slideshow) {
        slideshow.addEventListener('mouseenter', stopSlideshow);
        slideshow.addEventListener('mouseleave', startSlideshow);
    }
    
    // Initialize the slideshow
    startSlideshow();
}

/**
 * Get current year for copyright
 */
function getCurrentYear() {
    return new Date().getFullYear();
}

// Set copyright year in footer
document.addEventListener('DOMContentLoaded', function() {
    const yearElement = document.getElementById('currentYear');
    if (yearElement) {
        yearElement.textContent = getCurrentYear();
    }
});
