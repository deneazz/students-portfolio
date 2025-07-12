const Btns = document.querySelectorAll('.filter-btn');
const Cards = document.querySelectorAll('.project-card');
let activeFilters = [];

const allBtn = document.querySelector('.filter-btn[data-category="all"]');
allBtn.classList.add('active');

Btns.forEach(btn => {
    btn.addEventListener('click', function() {
        const category = this.dataset.category;
        
        if (category === 'all') {
            Btns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            activeFilters = [];
        } 
        else {
            allBtn.classList.remove('active');
            this.classList.toggle('active');
            
            if (this.classList.contains('active')) {
                activeFilters.push(category);
            } 
            else {
                activeFilters = activeFilters.filter(f => f !== category);
            }
            
            if (activeFilters.length === 0) {
                allBtn.classList.add('active');
            }
        }
        applyFilters();
    });
});

function applyFilters() {
    if (allBtn.classList.contains('active') || activeFilters.length === 0) {
        Cards.forEach(card => {
            card.style.display = 'flex';
        });
        return;
    }
    
    Cards.forEach(card => {
        const cardCategory = card.dataset.category;
        if (activeFilters.includes(cardCategory)) {
            card.style.display = 'flex';
        } 
        else {
            card.style.display = 'none';
        }
    });
}