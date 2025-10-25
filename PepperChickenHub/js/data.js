
// Default Menu Items
window.defaultMenuItems = [
    {
        id: 'item1',
        name: 'Basmatic Rice',
        description: 'Sold per Portion',
        price: 3000,
        category: 'Main',
        image: 'IMG_0907.jpg',
      
    },
    {
        id: 'item2',
        name: 'Pepper Soup',
        description: 'Spicy and aromatic soup made with catfish, beef or goat meat, enhanced with African spices and herbs.',
        price: 2200,
        category: 'Soup',
        image: 'https://source.unsplash.com/featured/800x600/?soup,spicy'
    },
    {
        id: 'item3',
        name: 'Suya',
        description: 'Skewered and grilled meat, coated with a mix of ground peanuts, spices, and chili peppers.',
        price: 1800,
        category: 'Appetizer',
        image: 'https://source.unsplash.com/featured/800x600/?kebab,meat'
    },
    {
        id: 'item4',
        name: 'Egusi Soup',
        description: 'Thick soup made with ground melon seeds and enhanced with leafy vegetables, spices, and meat.',
        price: 2000,
        category: 'Soup',
        image: 'https://source.unsplash.com/featured/800x600/?soup,african'
    },
    {
        id: 'item5',
        name: 'Pounded Yam',
        description: 'Smooth, stretchy dough made from boiled yams, traditionally eaten by hand with various soups.',
        price: 1200,
        category: 'Side',
        image: 'https://source.unsplash.com/featured/800x600/?yam,food'
    },
    {
        id: 'item6',
        name: 'Akara',
        description: 'Deep-fried bean cakes made from black-eyed peas, onions, and spices - a popular breakfast item.',
        price: 800,
        category: 'Breakfast',
        image: 'https://source.unsplash.com/featured/800x600/?fritters,food'
    },
    {
        id: 'item7',
        name: 'Moi Moi',
        description: 'Steamed bean pudding made from black-eyed peas, blended with onions and pepper.',
        price: 1000,
        category: 'Side',
        image: 'https://source.unsplash.com/featured/800x600/?pudding,food'
    },
    {
        id: 'item8',
        name: 'Ofada Rice',
        description: 'Local Nigerian rice variety served with a spicy sauce made from peppers, locust beans, and palm oil.',
        price: 1800,
        category: 'Main',
        image: 'https://source.unsplash.com/featured/800x600/?rice,food'
    },
    {
        id: 'item9',
        name: 'Assorted Meat (Gizdodo)',
        description: 'Gizzards and plantains sautéed in a spicy pepper sauce with bell peppers and onions.',
        price: 2500,
        category: 'Appetizer',
        image: 'https://source.unsplash.com/featured/800x600/?meat,food'
    },
    {
        id: 'item10',
        name: 'Chapman Drink',
        description: 'Nigerian cocktail made with Grenadine syrup, Fanta, and Sprite, mixed with sliced cucumber and orange.',
        price: 1200,
        category: 'Drink',
        image: 'https://source.unsplash.com/featured/800x600/?cocktail,drink'
    },
    {
        id: 'item11',
        name: 'Puff Puff',
        description: 'Sweet, deep-fried dough balls - a popular Nigerian snack and street food.',
        price: 700,
        category: 'Dessert',
        image: 'https://source.unsplash.com/featured/800x600/?doughnut,food'
    },
    {
        id: 'item12',
        name: 'Chin',
        description: 'Sweet, crunchy, bite-sized fried snack made from flour, sugar and other ingredients.',
        price: 600,
        category: 'Dessert',
        image: 'https://source.unsplash.com/featured/800x600/?snack,food'
    }
];

// Default Testimonials
window.defaultTestimonials = [
    {
        id: 'testimonial1',
        name: 'Adebayo Johnson',
        role: 'Food Critic',
        quote: 'The Jollof rice at Pepper Chicken is unmatched! It brings back memories of my grandmother\'s cooking with that authentic Nigerian taste.',
        rating: 5,
        image: 'https://source.unsplash.com/featured/300x300/?man,african'
    },
    {
        id: 'testimonial2',
        name: 'Chioma Okafor',
        role: 'Regular Customer',
        quote: 'I\'ve tried Nigerian food in many restaurants but the flavors at Pepper Chicken are truly authentic. Their Egusi soup is to die for!',
        rating: 5,
        image: 'https://source.unsplash.com/featured/300x300/?woman,african'
    },
    {
        id: 'testimonial3',
        name: 'Michael Smith',
        role: 'First-time Visitor',
        quote: 'My first time trying Nigerian cuisine and I\'m blown away! The staff were so helpful in explaining the menu and recommending dishes.',
        rating: 4,
        image: 'https://source.unsplash.com/featured/300x300/?man,tourist'
    }
];

// Default About Section Data
window.defaultAboutData = {
    title: 'Our Nigerian Culinary Story',
    subtitle: 'Authentic Tastes of Nigeria',
    content: 'Founded in 2010, Pepper Chicken brings the vibrant and diverse flavors of Nigerian cuisine to your table. Our recipes have been passed down through generations, preserving the authentic tastes and traditional cooking methods that make Nigerian food so special.\n\nWe source our ingredients from local farmers and use traditional cooking techniques to ensure every dish bursts with authentic flavors. Our chefs, born and raised in different regions of Nigeria, bring their unique regional expertise to create a diverse menu that showcases the country\'s rich culinary heritage.',
    image: 'https://source.unsplash.com/featured/800x600/?chef,african',
    features: [
        'Authentic Nigerian recipes',
        'Fresh, locally-sourced ingredients',
        'Traditional cooking methods',
        'Regional Nigerian specialties',
        'Homemade spice blends',
        'Family-friendly atmosphere'
    ]
};


// Default Contact Section Data
window.defaultContactData = {
    title: 'Get in Touch',
    subtitle: 'We\'d Love to Hear from You',
    address: '123 Spice Road, Lagos, Nigeria',
    phone: '+234 123 456 7890',
    email: 'info@pepperchicken.com',
    hours: 'Mon-Fri: 10am - 10pm | Sat-Sun: 12pm - 12am'
};

/**
 * Initialize website data on page load by loading from localStorage
 * or using default data if localStorage data doesn't exist
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize menu items
    initializeData('menuItems', window.defaultMenuItems);
    
    // Initialize testimonials
    initializeData('testimonials', window.defaultTestimonials);
    
    // Initialize about section data
    initializeData('aboutSection', window.defaultAboutData);
    
    // Initialize hero section data
    initializeData('heroSection', window.defaultHeroData);
    
    // Initialize contact section data
    initializeData('contactSection', window.defaultContactData);
    
    // Apply stored data to website elements
    applyStoredData();
});

/**
 * Initialize data in localStorage if it doesn't exist
 */
function initializeData(key, defaultData) {
    if (!localStorage.getItem(key)) {
        localStorage.setItem(key, JSON.stringify(defaultData));
    }
}

/**
 * Apply stored data to website elements
 */
function applyStoredData() {
    // Apply hero section data
   
    
    // Apply about section data
    applyAboutData();
    
    // Apply menu items data
    applyMenuData();
    
    // Apply testimonials data
    applyTestimonialsData();
    
    // Apply contact section data
    applyContactData();
}

/**
 * Apply hero section data from storage
 */
function applyHeroData() {
    const heroData = getDataFromStorage('heroSection', window.defaultHeroData);
    
    const heroTitle = document.querySelector('.hero h1');
    const heroSubtitle = document.querySelector('.hero h2');
    const heroButton = document.querySelector('.hero-buttons .btn');
    const heroSection = document.querySelector('.hero');
    
    if (heroTitle) heroTitle.textContent = heroData.title;
    if (heroSubtitle) heroSubtitle.textContent = heroData.subtitle;
    
    if (heroButton) {
        heroButton.textContent = heroData.buttonText;
        heroButton.href = heroData.buttonLink;
    }
    
    if (heroSection && heroData.image) {
        heroSection.style.backgroundImage = `linear-gradient(rgba(0, 0, 0, 0.6), rgba(0, 0, 0, 0.6)), url('${heroData.image}')`;
    }
}

/**
 * Apply about section data from storage
 */
function applyAboutData() {
    const aboutData = getDataFromStorage('aboutSection', window.defaultAboutData);
    
    const aboutTitle = document.querySelector('.about .section-title h2');
    const aboutSubtitle = document.querySelector('.about .about-subtitle');
    const aboutContent = document.querySelector('.about .about-content p');
    const aboutImage = document.querySelector('.about-image img');
    const aboutFeatures = document.querySelector('.about-features');
    
    if (aboutTitle) aboutTitle.textContent = aboutData.title;
    if (aboutSubtitle) aboutSubtitle.textContent = aboutData.subtitle;
    if (aboutContent) aboutContent.textContent = aboutData.content;
    
    if (aboutImage && aboutData.image) {
        aboutImage.src = aboutData.image;
        aboutImage.alt = aboutData.title;
    }
    
    if (aboutFeatures && aboutData.features && aboutData.features.length) {
        aboutFeatures.innerHTML = '';
        
        aboutData.features.forEach(feature => {
            const featureElement = document.createElement('div');
            featureElement.className = 'about-feature';
            featureElement.innerHTML = `
                <i class="fas fa-check-circle"></i>
                <span>${feature}</span>
            `;
            aboutFeatures.appendChild(featureElement);
        });
    }
}

/**
 * Apply menu items data from storage
 */
function applyMenuData() {
    const menuItems = getDataFromStorage('menuItems', window.defaultMenuItems);
    const menuContainer = document.getElementById('menuGrid');
    
    if (menuContainer) {
        // Use the displayMenuItems function from search.js if available, otherwise fallback to local rendering
        if (typeof displayMenuItems === 'function') {
            displayMenuItems(menuItems);
        } else {
            // Fallback rendering if search.js hasn't loaded yet
            menuContainer.innerHTML = '';
            
            menuItems.forEach(item => {
                const menuItem = document.createElement('div');
                menuItem.className = 'menu-item animate-on-scroll';
                menuItem.dataset.animation = 'fadeInUp';
                menuItem.dataset.id = item.id;
                
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
                
                // Add event listener for item click
                menuItem.addEventListener('click', function() {
                    if (typeof showItemDetail === 'function') {
                        showItemDetail(item);
                    }
                });
                
                // Add event listener for order button
                const orderBtn = menuItem.querySelector('.order-btn');
                if (orderBtn) {
                    orderBtn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        if (typeof addToCart === 'function') {
                            addToCart(item);
                        } else {
                            alert(`Added ${item.name} to cart!`);
                        }
                    });
                }
                
                menuContainer.appendChild(menuItem);
            });
            
            // Initialize animations
            if (typeof initializeItemAnimations === 'function') {
                initializeItemAnimations();
            }
        }
    }
}

/**
 * Apply testimonials data from storage
 */
function applyTestimonialsData() {
    const testimonials = getDataFromStorage('testimonials', window.defaultTestimonials);
    const testimonialsContainer = document.querySelector('.testimonials-container');
    
    if (testimonialsContainer) {
        const testimonialsSlider = testimonialsContainer.querySelector('.testimonial-slider');
        
        if (testimonialsSlider) {
            testimonialsSlider.innerHTML = '';
            
            testimonials.forEach(testimonial => {
                const slide = document.createElement('div');
                slide.className = 'testimonial-slide';
                
                // Generate star rating HTML
                let starsHtml = '';
                for (let i = 0; i < 5; i++) {
                    if (i < testimonial.rating) {
                        starsHtml += '<i class="fas fa-star"></i>';
                    } else {
                        starsHtml += '<i class="far fa-star"></i>';
                    }
                }
                
                const imageUrl = testimonial.image || 'https://source.unsplash.com/random/300x300/?person';
                
                slide.innerHTML = `
                    <div class="testimonial-img">
                        <img src="${imageUrl}" alt="${testimonial.name}">
                    </div>
                    <p class="testimonial-quote">${testimonial.quote}</p>
                    <div class="testimonial-author">${testimonial.name}</div>
                    <div class="testimonial-role">${testimonial.role}</div>
                    <div class="testimonial-rating">
                        ${starsHtml}
                    </div>
                `;
                
                testimonialsSlider.appendChild(slide);
            });
        }
    }
}

/**
 * Apply contact section data from storage
 */
function applyContactData() {
    const contactData = getDataFromStorage('contactSection', window.defaultContactData);
    
    const contactTitle = document.querySelector('.contact .section-title h2');
    const contactSubtitle = document.querySelector('.contact .section-title p');
    
    const addressText = document.querySelector('.contact-address .contact-text h3');
    const phoneText = document.querySelector('.contact-phone .contact-text h3');
    const emailText = document.querySelector('.contact-email .contact-text h3');
    const hoursText = document.querySelector('.contact-hours .contact-text h3');
    
    if (contactTitle) contactTitle.textContent = contactData.title;
    if (contactSubtitle) contactSubtitle.textContent = contactData.subtitle;
    
    if (addressText) addressText.textContent = contactData.address;
    if (phoneText) phoneText.textContent = contactData.phone;
    if (emailText) emailText.textContent = contactData.email;
    if (hoursText) hoursText.textContent = contactData.hours;
    
    // Also update footer contact info
    const footerAddress = document.querySelector('.footer-contact-address');
    const footerPhone = document.querySelector('.footer-contact-phone');
    const footerEmail = document.querySelector('.footer-contact-email');
    
    if (footerAddress) footerAddress.textContent = contactData.address;
    if (footerPhone) footerPhone.textContent = contactData.phone;
    if (footerEmail) footerEmail.textContent = contactData.email;
}

/**
 * Get data from storage or use default if not found
 */
function getDataFromStorage(key, defaultData) {
    const storedData = localStorage.getItem(key);
    return storedData ? JSON.parse(storedData) : defaultData;
}
