/**
 * Pepper Chicken - Nigerian Restaurant Website
 * Search Functionality
 * 
 * This file contains the search functionality for the menu items
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeSearch();
});

/**
 * Initialize the search functionality
 */
function initializeSearch() {
    const searchForm = document.getElementById('searchForm');
    const searchInput = document.getElementById('searchInput');
    const menuContainer = document.getElementById('menuGrid');
    const menuNavItems = document.querySelectorAll('.menu-nav-item');
    const noResultsMessage = document.getElementById('noResults');
    
    if (!searchForm || !searchInput || !menuContainer) return;
    
    // Load all menu items initially
    loadMenuItems();
    
    // Event listener for search form submission
    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const searchTerm = searchInput.value.trim().toLowerCase();
        searchMenuItems(searchTerm);
    });
    
    // Event listener for real-time search as user types
    searchInput.addEventListener('input', function() {
        const searchTerm = searchInput.value.trim().toLowerCase();
        searchMenuItems(searchTerm);
    });
    
    // Event listeners for category filter buttons
    menuNavItems.forEach(item => {
        item.addEventListener('click', function() {
            const category = this.getAttribute('data-category');
            
            // Reset search input
            searchInput.value = '';
            
            // Update active class
            menuNavItems.forEach(navItem => navItem.classList.remove('active'));
            this.classList.add('active');
            
            // Filter menu items by category
            if (category === 'all') {
                loadMenuItems();
            } else {
                filterMenuItemsByCategory(category);
            }
        });
    });
}

/**
 * Search menu items based on search term
 */
function searchMenuItems(searchTerm) {
    // Get all menu items from data store
    const menuItems = getMenuItemsFromDataStore();
    
    // If search term is empty, show all items
    if (!searchTerm) {
        displayMenuItems(menuItems);
        return;
    }
    
    searchTerm = searchTerm.toLowerCase();
    
    // Filter items based on search term
    const filteredItems = menuItems.filter(item => {
        return (
            item.name.toLowerCase().includes(searchTerm) ||
            item.description.toLowerCase().includes(searchTerm) ||
            item.category.toLowerCase().includes(searchTerm) ||
            item.price.toString().includes(searchTerm)
        );
    });
    
    console.log(`Search term: "${searchTerm}". Found ${filteredItems.length} matching items.`);
    
    // Display filtered items
    displayMenuItems(filteredItems);
}

/**
 * Filter menu items by category
 */
function filterMenuItemsByCategory(category) {
    const menuItems = getMenuItemsFromDataStore();
    
    const filteredItems = menuItems.filter(item => 
        item.category.toLowerCase() === category.toLowerCase()
    );
    
    displayMenuItems(filteredItems);
}

/**
 * Load all menu items
 */
function loadMenuItems() {
    const menuItems = getMenuItemsFromDataStore();
    displayMenuItems(menuItems);
}

/**
 * Get menu items from the data store
 */
function getMenuItemsFromDataStore() {
    // First try to get from localStorage for any admin updates
    const storedItems = localStorage.getItem('menuItems');
    
    if (storedItems) {
        return JSON.parse(storedItems);
    }
    
    // If no stored items, return the default menu items
    return window.defaultMenuItems || [];
}

/**
 * Display menu items in the container
 */
function displayMenuItems(items) {
    const menuContainer = document.getElementById('menuGrid');
    const noResultsMessage = document.getElementById('noResults');
    
    if (!menuContainer) return;
    
    // Clear existing content
    menuContainer.innerHTML = '';
    
    // Show no results message if no items found
    if (items.length === 0) {
        noResultsMessage.style.display = 'block';
        return;
    }
    
    // Hide no results message
    if (noResultsMessage) {
        noResultsMessage.style.display = 'none';
    }
    
    // Loop through items and create HTML
    items.forEach(item => {
        const menuItemElement = createMenuItemElement(item);
        menuContainer.appendChild(menuItemElement);
    });
    
    // Initialize animations for new elements
    initializeItemAnimations();
}

/**
 * Create a menu item element
 */
function createMenuItemElement(item) {
    const menuItem = document.createElement('div');
    menuItem.className = 'menu-item animate-on-scroll';
    menuItem.dataset.animation = 'fadeInUp';
    menuItem.dataset.id = item.id;
    
    // Create image style with placeholder or actual image
    const imageStyle = item.image 
        ? `background-image: url('${item.image}');` 
        : `background-color: var(--grey-medium);`;
    
    menuItem.innerHTML = `
        <div class="menu-category">${item.category}</div>
        <div class="menu-item-img" style="${imageStyle}"></div>
        <div class="menu-item-content">
            <h3 class="menu-item-title">${item.name}</h3>
            <p class="menu-item-desc">${item.description}</p>
            <div class="menu-item-footer">
                <div class="menu-item-price">₦${item.price.toLocaleString()}</div>
                <button class="btn btn-sm order-btn">Order Now</button>
            </div>
        </div>
    `;
    
    // Add event listener to the menu item for interactive display
    menuItem.addEventListener('click', function() {
        showItemDetail(item);
    });
    
    // Get the order button inside the menu item
    const orderBtn = menuItem.querySelector('.order-btn');
    if (orderBtn) {
        // Prevent the click on the order button from triggering the menu item click
        orderBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            addToCart(item);
        });
    }
    
    return menuItem;
}

/**
 * Show item details in a modal
 */
function showItemDetail(item) {
    // Check if modal exists, otherwise create it
    let modal = document.getElementById('menuItemModal');
    
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'menuItemModal';
        modal.className = 'menu-modal';
        document.body.appendChild(modal);
    }
    
    // Create modal content
    modal.innerHTML = `
        <div class="menu-modal-content">
            <span class="menu-modal-close">&times;</span>
            <div class="menu-modal-img" style="background-image: url('${item.image}');"></div>
            <div class="menu-modal-info">
                <h2>${item.name}</h2>
                <div class="menu-modal-category">${item.category}</div>
                <div class="menu-modal-price">₦${item.price.toLocaleString()}</div>
                <p>${item.description}</p>
                <div class="menu-modal-actions">
                    <button class="btn btn-accent add-to-cart-btn">Add to Cart</button>
                    <button class="btn btn-outline view-menu-btn">Back to Menu</button>
                </div>
            </div>
        </div>
    `;
    
    // Show the modal
    modal.style.display = 'block';
    
    // Add event listeners
    const closeBtn = modal.querySelector('.menu-modal-close');
    const addToCartBtn = modal.querySelector('.add-to-cart-btn');
    const viewMenuBtn = modal.querySelector('.view-menu-btn');
    
    if (closeBtn) {
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    if (addToCartBtn) {
        addToCartBtn.addEventListener('click', function() {
            addToCart(item);
            modal.style.display = 'none';
        });
    }
    
    if (viewMenuBtn) {
        viewMenuBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }
    
    // Close the modal when clicking outside of it
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

/**
 * Add an item to cart
 */
function addToCart(item) {
    // This is a placeholder for actual cart functionality
    alert(`Added ${item.name} to cart!`);
    
    // In a real implementation, you would:
    // 1. Store the item in localStorage or state
    // 2. Update the cart UI
    // 3. Show a confirmation message
}

/**
 * Initialize animations for newly added items
 */
function initializeItemAnimations() {
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
}
