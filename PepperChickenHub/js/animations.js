/**
 * Pepper Chicken - Nigerian Restaurant Website
 * Animation Effects
 * 
 * This file contains custom animation effects for the website
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeAnimations();
    initializeHeroAnimation();
    initializeFeatureAnimations();
    initializeScrollAnimations();
});

/**
 * Initialize all animations
 */
function initializeAnimations() {
    // Add animated class to elements with animation data attributes
    const animatedElements = document.querySelectorAll('[data-animation]');
    
    animatedElements.forEach(element => {
        const animationClass = element.dataset.animation;
        element.classList.add(animationClass);
    });
}

/**
 * Initialize hero section animations
 */
function initializeHeroAnimation() {
    const heroSection = document.querySelector('.hero');
    
    if (!heroSection) return;
    
    // Create pepper background particles
    createPepperParticles(heroSection);
    
    // Add staggered animation to hero content
    const heroContent = document.querySelector('.hero-container');
    if (heroContent) {
        const children = heroContent.children;
        Array.from(children).forEach((child, index) => {
            child.style.opacity = '0';
            child.style.animation = `fadeInUp 0.8s ${index * 0.2}s forwards`;
        });
    }
}

/**
 * Create pepper-shaped particles in the background
 */
function createPepperParticles(container) {
    const numParticles = 20;
    
    for (let i = 0; i < numParticles; i++) {
        const particle = document.createElement('div');
        particle.className = 'pepper-particle';
        
        // Random size
        const size = Math.random() * 30 + 10;
        
        // Random position
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        
        // Random rotation
        const rotation = Math.random() * 360;
        
        // Random animation duration
        const duration = Math.random() * 20 + 10;
        
        // Random delay
        const delay = Math.random() * 5;
        
        // Apply styles
        particle.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size * 2}px;
            background-color: rgba(230, 57, 70, 0.15);
            border-radius: 50% 50% 50% 50% / 60% 60% 40% 40%;
            top: ${posY}%;
            left: ${posX}%;
            transform: rotate(${rotation}deg);
            animation: floatParticle ${duration}s ${delay}s infinite linear;
            z-index: 0;
        `;
        
        container.appendChild(particle);
    }
    
    // Add keyframes for floating animation
    if (!document.getElementById('pepper-animations')) {
        const style = document.createElement('style');
        style.id = 'pepper-animations';
        style.innerHTML = `
            @keyframes floatParticle {
                0% {
                    transform: rotate(${Math.random() * 360}deg) translate(0, 0);
                }
                25% {
                    transform: rotate(${Math.random() * 360}deg) translate(${Math.random() * 50 - 25}px, ${Math.random() * 50 - 25}px);
                }
                50% {
                    transform: rotate(${Math.random() * 360}deg) translate(${Math.random() * 100 - 50}px, ${Math.random() * 100 - 50}px);
                }
                75% {
                    transform: rotate(${Math.random() * 360}deg) translate(${Math.random() * 50 - 25}px, ${Math.random() * 50 - 25}px);
                }
                100% {
                    transform: rotate(${Math.random() * 360}deg) translate(0, 0);
                }
            }
        `;
        document.head.appendChild(style);
    }
}

/**
 * Initialize animations for feature items
 */
function initializeFeatureAnimations() {
    const featuredItems = document.querySelectorAll('.featured-item');
    
    featuredItems.forEach(item => {
        // Add hover animation
        item.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px)';
            this.style.boxShadow = '0 15px 30px rgba(0, 0, 0, 0.15)';
        });
        
        item.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 6px 12px rgba(0, 0, 0, 0.1)';
        });
    });
}

/**
 * Initialize scroll-based animations
 */
function initializeScrollAnimations() {
    const animatedElements = document.querySelectorAll('.animate-on-scroll');
    
    // Create intersection observer
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const element = entry.target;
                const delay = element.dataset.delay || 0;
                
                // Add animated class after specified delay
                setTimeout(() => {
                    element.classList.add('animated');
                }, delay * 1000);
                
                // Stop observing after animation
                observer.unobserve(element);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    });
    
    // Observe all elements
    animatedElements.forEach(element => {
        observer.observe(element);
    });
}

/**
 * Create staggered animation for a group of elements
 */
function createStaggeredAnimation(selector, animationClass, delayBetween = 0.1) {
    const elements = document.querySelectorAll(selector);
    
    elements.forEach((element, index) => {
        element.style.opacity = '0';
        element.style.animationDelay = `${index * delayBetween}s`;
        element.classList.add(animationClass);
    });
}

/**
 * Initialize menu item hover effects
 */
function initializeMenuItemEffects() {
    const menuItems = document.querySelectorAll('.menu-item');
    
    menuItems.forEach(item => {
        item.addEventListener('mouseenter', function() {
            this.querySelector('.menu-item-img').style.transform = 'scale(1.05)';
        });
        
        item.addEventListener('mouseleave', function() {
            this.querySelector('.menu-item-img').style.transform = 'scale(1)';
        });
    });
}

// Initialize additional effects when the page is fully loaded
window.addEventListener('load', function() {
    initializeMenuItemEffects();
    
    // Add staggered animation to menu items
    createStaggeredAnimation('.menu-item', 'fadeInUp', 0.1);
    
    // Add staggered animation to about features
    createStaggeredAnimation('.about-feature', 'fadeInRight', 0.2);
    
    // Add staggered animation to footer columns
    createStaggeredAnimation('.footer-col', 'fadeIn', 0.2);
});

/**
 * Text animation for headings
 */
function animateText(element) {
    if (!element) return;
    
    const text = element.innerText;
    element.innerHTML = '';
    
    // Create spans for each character
    for (let i = 0; i < text.length; i++) {
        const span = document.createElement('span');
        span.innerText = text[i];
        span.style.opacity = '0';
        span.style.animation = `fadeIn 0.5s ${i * 0.05}s forwards`;
        element.appendChild(span);
    }
}

// Apply text animation to main headings
document.addEventListener('DOMContentLoaded', function() {
    const mainHeadings = document.querySelectorAll('.section-title h2');
    mainHeadings.forEach(heading => {
        // Add animation when heading comes into view
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                animateText(heading);
                observer.unobserve(heading);
            }
        });
        
        observer.observe(heading);
    });
});
