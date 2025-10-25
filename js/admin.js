/**
 * Pepper Chicken - Nigerian Restaurant Website
 * Admin Dashboard JavaScript
 * 
 * This file contains the functionality for the admin dashboard
 * including content management and local storage operations.
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeAdmin();
});

/**
 * Initialize the admin dashboard
 */
function initializeAdmin() {
    // Handle admin login
    initializeLogin();
    
    // Check if user is logged in
    if (isLoggedIn()) {
        // Initialize dashboard components
        initializeSidebar();
        initializeContentEditors();
        initializeLogout();
        loadContentFromStorage();
        showDashboardSection();
    }
}

/**
 * Initialize the login functionality
 */
function initializeLogin() {
    const loginForm = document.getElementById('loginForm');
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // Simple authentication - in a real app this would be more secure
            if (username === 'admin' && password === 'pepperchicken2023') {
                // Set login status in localStorage
                localStorage.setItem('adminLoggedIn', 'true');
                
                // Redirect to dashboard
                window.location.href = '/admin/dashboard';
            } else {
                showAlert('Invalid username or password', 'error');
            }
        });
    }
}

/**
 * Initialize sidebar functionality
 */
function initializeSidebar() {
    const sidebarItems = document.querySelectorAll('.admin-nav-link');
    const contentSections = document.querySelectorAll('.admin-section');
    
    // Add click event to sidebar items
    sidebarItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all sidebar items
            sidebarItems.forEach(i => i.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Hide all content sections
            contentSections.forEach(section => {
                section.style.display = 'none';
            });
            
            // Show selected section
            const targetSection = document.getElementById(this.getAttribute('data-section'));
            if (targetSection) {
                targetSection.style.display = 'block';
            }
        });
    });
    
    // Mobile menu toggle
    const menuToggle = document.querySelector('.menu-toggle');
    const sidebar = document.querySelector('.admin-sidebar');
    
    if (menuToggle) {
        menuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }
}

/**
 * Initialize content editors
 */
function initializeContentEditors() {
    // Initialize hero section editor
    initializeHeroEditor();
    
    // Initialize about section editor
    initializeAboutEditor();
    
    // Initialize menu section editor
    initializeMenuEditor();
    
    // Initialize testimonial section editor
    initializeTestimonialsEditor();
    
    // Initialize contact section editor
    initializeContactEditor();
}

/**
 * Initialize hero section editor
 */
function initializeHeroEditor() {
    const heroForm = document.getElementById('heroForm');
    
    if (heroForm) {
        // Load existing data
        const heroData = getFromStorage('heroSection');
        
        if (heroData) {
            document.getElementById('heroTitle').value = heroData.title || '';
            document.getElementById('heroSubtitle').value = heroData.subtitle || '';
            document.getElementById('heroButtonText').value = heroData.buttonText || '';
            document.getElementById('heroButtonLink').value = heroData.buttonLink || '';
            document.getElementById('heroImage').value = heroData.image || '';
        }
        
        // Save hero section data
        heroForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const heroData = {
                title: document.getElementById('heroTitle').value,
                subtitle: document.getElementById('heroSubtitle').value,
                buttonText: document.getElementById('heroButtonText').value,
                buttonLink: document.getElementById('heroButtonLink').value,
                image: document.getElementById('heroImage').value
            };
            
            saveToStorage('heroSection', heroData);
            showAlert('Hero section updated successfully', 'success');
        });
    }
}

/**
 * Initialize about section editor
 */
function initializeAboutEditor() {
    const aboutForm = document.getElementById('aboutForm');
    
    if (aboutForm) {
        // Load existing data
        const aboutData = getFromStorage('aboutSection');
        
        if (aboutData) {
            document.getElementById('aboutTitle').value = aboutData.title || '';
            document.getElementById('aboutSubtitle').value = aboutData.subtitle || '';
            document.getElementById('aboutContent').value = aboutData.content || '';
            document.getElementById('aboutImage').value = aboutData.image || '';
            
            // Load features
            if (aboutData.features && aboutData.features.length) {
                const featuresContainer = document.getElementById('aboutFeatures');
                featuresContainer.innerHTML = '';
                
                aboutData.features.forEach((feature, index) => {
                    addFeatureInput(featuresContainer, feature, index);
                });
            }
        }
        
        // Add feature button
        const addFeatureBtn = document.getElementById('addFeatureBtn');
        if (addFeatureBtn) {
            addFeatureBtn.addEventListener('click', function() {
                const featuresContainer = document.getElementById('aboutFeatures');
                const featureCount = featuresContainer.children.length;
                
                addFeatureInput(featuresContainer, '', featureCount);
            });
        }
        
        // Save about section data
        aboutForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Collect feature data
            const features = [];
            const featureInputs = document.querySelectorAll('.feature-input');
            
            featureInputs.forEach(input => {
                const value = input.value.trim();
                if (value) {
                    features.push(value);
                }
            });
            
            const aboutData = {
                title: document.getElementById('aboutTitle').value,
                subtitle: document.getElementById('aboutSubtitle').value,
                content: document.getElementById('aboutContent').value,
                image: document.getElementById('aboutImage').value,
                features: features
            };
            
            saveToStorage('aboutSection', aboutData);
            showAlert('About section updated successfully', 'success');
        });
    }
}

/**
 * Add feature input field to container
 */
function addFeatureInput(container, value = '', index) {
    const featureGroup = document.createElement('div');
    featureGroup.className = 'form-group';
    
    featureGroup.innerHTML = `
        <div class="feature-row">
            <input type="text" class="form-control feature-input" placeholder="Feature ${index + 1}" value="${value}">
            <button type="button" class="btn btn-sm delete feature-delete-btn">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    
    container.appendChild(featureGroup);
    
    // Add delete event listener
    const deleteBtn = featureGroup.querySelector('.feature-delete-btn');
    deleteBtn.addEventListener('click', function() {
        container.removeChild(featureGroup);
    });
}

/**
 * Initialize menu section editor
 */
function initializeMenuEditor() {
    const menuItemsList = document.getElementById('menuItemsList');
    const addMenuItemBtn = document.getElementById('addMenuItemBtn');
    const menuForm = document.getElementById('menuForm');
    
    if (menuItemsList && addMenuItemBtn) {
        // Load existing menu items
        loadMenuItems();
        
        // Add new menu item button
        addMenuItemBtn.addEventListener('click', function() {
            showMenuItemEditor();
        });
        
        // Menu form submission
        if (menuForm) {
            menuForm.addEventListener('submit', function(e) {
                e.preventDefault();
                saveMenuItem();
            });
        }
    }
}

/**
 * Load menu items into admin panel
 */
function loadMenuItems() {
    const menuItemsList = document.getElementById('menuItemsList');
    if (!menuItemsList) return;
    
    // Clear list
    menuItemsList.innerHTML = '';
    
    // Get menu items from storage
    const menuItems = getFromStorage('menuItems') || window.defaultMenuItems || [];
    
    // Create list items
    menuItems.forEach((item, index) => {
        const listItem = document.createElement('div');
        listItem.className = 'content-item';
        listItem.innerHTML = `
            <div class="content-item-icon">
                <i class="fas fa-utensils"></i>
            </div>
            <div class="content-item-title">${item.name}</div>
            <div class="content-item-actions">
                <button class="action-btn edit" data-index="${index}">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="action-btn delete" data-index="${index}">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        
        menuItemsList.appendChild(listItem);
        
        // Add edit and delete event listeners
        const editBtn = listItem.querySelector('.edit');
        const deleteBtn = listItem.querySelector('.delete');
        
        editBtn.addEventListener('click', function() {
            const index = this.getAttribute('data-index');
            editMenuItem(index);
        });
        
        deleteBtn.addEventListener('click', function() {
            const index = this.getAttribute('data-index');
            deleteMenuItem(index);
        });
    });
}

/**
 * Show menu item editor for adding new item
 */
function showMenuItemEditor(itemData = null) {
    const editorSection = document.getElementById('menuItemEditor');
    const menuItemsList = document.getElementById('menuItemsList');
    
    if (editorSection && menuItemsList) {
        // Show editor, hide list
        editorSection.style.display = 'block';
        menuItemsList.parentElement.style.display = 'none';
        
        // Clear form or fill with data if editing
        const nameInput = document.getElementById('menuItemName');
        const descInput = document.getElementById('menuItemDescription');
        const priceInput = document.getElementById('menuItemPrice');
        const categoryInput = document.getElementById('menuItemCategory');
        const imageInput = document.getElementById('menuItemImage');
        const itemIdInput = document.getElementById('menuItemId');
        
        if (itemData) {
            nameInput.value = itemData.name || '';
            descInput.value = itemData.description || '';
            priceInput.value = itemData.price || '';
            categoryInput.value = itemData.category || '';
            imageInput.value = itemData.image || '';
            itemIdInput.value = itemData.id || '';
        } else {
            nameInput.value = '';
            descInput.value = '';
            priceInput.value = '';
            categoryInput.value = '';
            imageInput.value = '';
            itemIdInput.value = '';
        }
    }
}

/**
 * Save menu item
 */
function saveMenuItem() {
    const nameInput = document.getElementById('menuItemName');
    const descInput = document.getElementById('menuItemDescription');
    const priceInput = document.getElementById('menuItemPrice');
    const categoryInput = document.getElementById('menuItemCategory');
    const imageInput = document.getElementById('menuItemImage');
    const itemIdInput = document.getElementById('menuItemId');
    
    // Validate inputs
    if (!nameInput.value || !descInput.value || !priceInput.value || !categoryInput.value) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    
    // Get existing menu items
    let menuItems = getFromStorage('menuItems') || window.defaultMenuItems || [];
    
    // Create new item object
    const menuItem = {
        id: itemIdInput.value || Date.now().toString(),
        name: nameInput.value,
        description: descInput.value,
        price: parseFloat(priceInput.value),
        category: categoryInput.value,
        image: imageInput.value
    };
    
    // Check if editing or adding new
    if (itemIdInput.value) {
        // Find the item with matching id and update it
        menuItems = menuItems.map(item => {
            if (item.id === itemIdInput.value) {
                return menuItem;
            }
            return item;
        });
    } else {
        // Add new item
        menuItems.push(menuItem);
    }
    
    // Save to storage
    saveToStorage('menuItems', menuItems);
    
    // Show success message
    showAlert('Menu item saved successfully', 'success');
    
    // Return to menu items list
    const editorSection = document.getElementById('menuItemEditor');
    const menuItemsList = document.getElementById('menuItemsList');
    
    if (editorSection && menuItemsList) {
        editorSection.style.display = 'none';
        menuItemsList.parentElement.style.display = 'block';
        
        // Reload menu items
        loadMenuItems();
    }
}

/**
 * Edit menu item
 */
function editMenuItem(index) {
    // Get menu items
    const menuItems = getFromStorage('menuItems') || window.defaultMenuItems || [];
    
    // Get item data
    const itemData = menuItems[index];
    
    // Show editor with item data
    showMenuItemEditor(itemData);
}

/**
 * Delete menu item
 */
function deleteMenuItem(index) {
    if (confirm('Are you sure you want to delete this menu item?')) {
        // Get menu items
        let menuItems = getFromStorage('menuItems') || window.defaultMenuItems || [];
        
        // Remove item at index
        menuItems.splice(index, 1);
        
        // Save to storage
        saveToStorage('menuItems', menuItems);
        
        // Reload menu items
        loadMenuItems();
        
        // Show success message
        showAlert('Menu item deleted successfully', 'success');
    }
}

/**
 * Initialize testimonials editor
 */
function initializeTestimonialsEditor() {
    const testimonialsList = document.getElementById('testimonialsList');
    const addTestimonialBtn = document.getElementById('addTestimonialBtn');
    const testimonialForm = document.getElementById('testimonialForm');
    
    if (testimonialsList && addTestimonialBtn) {
        // Load existing testimonials
        loadTestimonials();
        
        // Add new testimonial button
        addTestimonialBtn.addEventListener('click', function() {
            showTestimonialEditor();
        });
        
        // Testimonial form submission
        if (testimonialForm) {
            testimonialForm.addEventListener('submit', function(e) {
                e.preventDefault();
                saveTestimonial();
            });
        }
    }
}

/**
 * Load testimonials into admin panel
 */
function loadTestimonials() {
    const testimonialsList = document.getElementById('testimonialsList');
    if (!testimonialsList) return;
    
    // Clear list
    testimonialsList.innerHTML = '';
    
    // Get testimonials from storage
    const testimonials = getFromStorage('testimonials') || window.defaultTestimonials || [];
    
    // Create list items
    testimonials.forEach((item, index) => {
        const listItem = document.createElement('div');
        listItem.className = 'content-item';
        listItem.innerHTML = `
            <div class="content-item-icon">
                <i class="fas fa-quote-right"></i>
            </div>
            <div class="content-item-title">${item.name}</div>
            <div class="content-item-actions">
                <button class="action-btn edit" data-index="${index}">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="action-btn delete" data-index="${index}">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        
        testimonialsList.appendChild(listItem);
        
        // Add edit and delete event listeners
        const editBtn = listItem.querySelector('.edit');
        const deleteBtn = listItem.querySelector('.delete');
        
        editBtn.addEventListener('click', function() {
            const index = this.getAttribute('data-index');
            editTestimonial(index);
        });
        
        deleteBtn.addEventListener('click', function() {
            const index = this.getAttribute('data-index');
            deleteTestimonial(index);
        });
    });
}

/**
 * Show testimonial editor for adding new testimonial
 */
function showTestimonialEditor(testimonialData = null) {
    const editorSection = document.getElementById('testimonialEditor');
    const testimonialsList = document.getElementById('testimonialsList');
    
    if (editorSection && testimonialsList) {
        // Show editor, hide list
        editorSection.style.display = 'block';
        testimonialsList.parentElement.style.display = 'none';
        
        // Clear form or fill with data if editing
        const nameInput = document.getElementById('testimonialName');
        const roleInput = document.getElementById('testimonialRole');
        const quoteInput = document.getElementById('testimonialQuote');
        const ratingInput = document.getElementById('testimonialRating');
        const imageInput = document.getElementById('testimonialImage');
        const idInput = document.getElementById('testimonialId');
        
        if (testimonialData) {
            nameInput.value = testimonialData.name || '';
            roleInput.value = testimonialData.role || '';
            quoteInput.value = testimonialData.quote || '';
            ratingInput.value = testimonialData.rating || 5;
            imageInput.value = testimonialData.image || '';
            idInput.value = testimonialData.id || '';
        } else {
            nameInput.value = '';
            roleInput.value = '';
            quoteInput.value = '';
            ratingInput.value = 5;
            imageInput.value = '';
            idInput.value = '';
        }
    }
}

/**
 * Save testimonial
 */
function saveTestimonial() {
    const nameInput = document.getElementById('testimonialName');
    const roleInput = document.getElementById('testimonialRole');
    const quoteInput = document.getElementById('testimonialQuote');
    const ratingInput = document.getElementById('testimonialRating');
    const imageInput = document.getElementById('testimonialImage');
    const idInput = document.getElementById('testimonialId');
    
    // Validate inputs
    if (!nameInput.value || !quoteInput.value) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    
    // Get existing testimonials
    let testimonials = getFromStorage('testimonials') || window.defaultTestimonials || [];
    
    // Create new testimonial object
    const testimonial = {
        id: idInput.value || Date.now().toString(),
        name: nameInput.value,
        role: roleInput.value,
        quote: quoteInput.value,
        rating: parseInt(ratingInput.value),
        image: imageInput.value
    };
    
    // Check if editing or adding new
    if (idInput.value) {
        // Find the testimonial with matching id and update it
        testimonials = testimonials.map(item => {
            if (item.id === idInput.value) {
                return testimonial;
            }
            return item;
        });
    } else {
        // Add new testimonial
        testimonials.push(testimonial);
    }
    
    // Save to storage
    saveToStorage('testimonials', testimonials);
    
    // Show success message
    showAlert('Testimonial saved successfully', 'success');
    
    // Return to testimonials list
    const editorSection = document.getElementById('testimonialEditor');
    const testimonialsList = document.getElementById('testimonialsList');
    
    if (editorSection && testimonialsList) {
        editorSection.style.display = 'none';
        testimonialsList.parentElement.style.display = 'block';
        
        // Reload testimonials
        loadTestimonials();
    }
}

/**
 * Edit testimonial
 */
function editTestimonial(index) {
    // Get testimonials
    const testimonials = getFromStorage('testimonials') || window.defaultTestimonials || [];
    
    // Get testimonial data
    const testimonialData = testimonials[index];
    
    // Show editor with testimonial data
    showTestimonialEditor(testimonialData);
}

/**
 * Delete testimonial
 */
function deleteTestimonial(index) {
    if (confirm('Are you sure you want to delete this testimonial?')) {
        // Get testimonials
        let testimonials = getFromStorage('testimonials') || window.defaultTestimonials || [];
        
        // Remove testimonial at index
        testimonials.splice(index, 1);
        
        // Save to storage
        saveToStorage('testimonials', testimonials);
        
        // Reload testimonials
        loadTestimonials();
        
        // Show success message
        showAlert('Testimonial deleted successfully', 'success');
    }
}

/**
 * Initialize contact section editor
 */
function initializeContactEditor() {
    const contactForm = document.getElementById('contactInfoForm');
    
    if (contactForm) {
        // Load existing data
        const contactData = getFromStorage('contactSection');
        
        if (contactData) {
            document.getElementById('contactTitle').value = contactData.title || '';
            document.getElementById('contactSubtitle').value = contactData.subtitle || '';
            document.getElementById('contactAddress').value = contactData.address || '';
            document.getElementById('contactPhone').value = contactData.phone || '';
            document.getElementById('contactEmail').value = contactData.email || '';
            document.getElementById('contactHours').value = contactData.hours || '';
        }
        
        // Save contact section data
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const contactData = {
                title: document.getElementById('contactTitle').value,
                subtitle: document.getElementById('contactSubtitle').value,
                address: document.getElementById('contactAddress').value,
                phone: document.getElementById('contactPhone').value,
                email: document.getElementById('contactEmail').value,
                hours: document.getElementById('contactHours').value
            };
            
            saveToStorage('contactSection', contactData);
            showAlert('Contact information updated successfully', 'success');
        });
    }
}

/**
 * Load content from storage when admin dashboard loads
 */
function loadContentFromStorage() {
    // Make sure there's default data in the storage
    initializeDefaultData();
}

/**
 * Initialize default data if not already in storage
 */
function initializeDefaultData() {
    // Check if menu items exist in storage
    if (!localStorage.getItem('menuItems')) {
        // Save default menu items if they exist
        if (window.defaultMenuItems) {
            saveToStorage('menuItems', window.defaultMenuItems);
        }
    }
    
    // Check if testimonials exist in storage
    if (!localStorage.getItem('testimonials')) {
        // Save default testimonials if they exist
        if (window.defaultTestimonials) {
            saveToStorage('testimonials', window.defaultTestimonials);
        }
    }
}

/**
 * Show the first dashboard section by default
 */
function showDashboardSection() {
    const firstNavItem = document.querySelector('.admin-nav-link');
    if (firstNavItem) {
        firstNavItem.click();
    }
}

/**
 * Initialize logout functionality
 */
function initializeLogout() {
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Clear login status
            localStorage.removeItem('adminLoggedIn');
            
            // Redirect to login page
            window.location.href = '/admin/login';
        });
    }
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return localStorage.getItem('adminLoggedIn') === 'true';
}

/**
 * Save data to localStorage
 */
function saveToStorage(key, data) {
    localStorage.setItem(key, JSON.stringify(data));
}

/**
 * Get data from localStorage
 */
function getFromStorage(key) {
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : null;
}

/**
 * Show alert message
 */
function showAlert(message, type = 'success') {
    const alertsContainer = document.getElementById('alerts');
    
    if (alertsContainer) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = message;
        
        alertsContainer.appendChild(alert);
        
        // Remove alert after 3 seconds
        setTimeout(() => {
            alert.remove();
        }, 3000);
    }
}
