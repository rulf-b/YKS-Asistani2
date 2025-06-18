// Tema değiştirme fonksiyonu
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const themeIcon = document.querySelector('#theme-toggle i');
    themeIcon.className = newTheme === 'dark' ? 'bi bi-moon-fill' : 'bi bi-sun-fill';
}

// Sayfa yüklendiğinde tema kontrolü
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    const themeIcon = document.querySelector('#theme-toggle i');
    themeIcon.className = savedTheme === 'dark' ? 'bi bi-moon-fill' : 'bi bi-sun-fill';
    
    // Tema değiştirme butonu click eventi
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
    
    // Form doğrulama
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
    
    // Toast mesajları
    const toastElList = document.querySelectorAll('.toast');
    Array.from(toastElList).forEach(toastEl => {
        const toast = new bootstrap.Toast(toastEl, {
            autohide: true,
            delay: 5000
        });
        toast.show();
    });
    
    // Checkbox animasyonu
    const checkboxes = document.querySelectorAll('.form-check-input');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const listItem = this.closest('.list-group-item');
            if (this.checked) {
                listItem.style.opacity = '0.5';
                listItem.style.textDecoration = 'line-through';
            } else {
                listItem.style.opacity = '1';
                listItem.style.textDecoration = 'none';
            }
        });
    });
    
    // Bildirim badge'i animasyonu
    const notificationBadge = document.querySelector('.notification-badge');
    if (notificationBadge) {
        notificationBadge.classList.add('pulse');
    }
    
    // Grafik animasyonları
    const chartContainers = document.querySelectorAll('.chart-container');
    chartContainers.forEach(container => {
        container.style.opacity = '0';
        container.style.transform = 'translateY(20px)';
        
        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    container.style.transition = 'all 0.6s ease-out';
                    container.style.opacity = '1';
                    container.style.transform = 'translateY(0)';
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        
        observer.observe(container);
    });
    
    // Dropdown menü pozisyonu ayarlama
    const dropdowns = document.querySelectorAll('.dropdown-menu');
    dropdowns.forEach(dropdown => {
        const parent = dropdown.parentElement;
        const parentRect = parent.getBoundingClientRect();
        const viewportHeight = window.innerHeight;
        
        if (parentRect.bottom + dropdown.offsetHeight > viewportHeight) {
            dropdown.style.top = 'auto';
            dropdown.style.bottom = '100%';
        }
    });
    
    // Smooth scroll
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Responsive tablo
    const tables = document.querySelectorAll('table');
    tables.forEach(table => {
        const wrapper = document.createElement('div');
        wrapper.className = 'table-responsive';
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
    
    // Input focus efekti
    const inputs = document.querySelectorAll('.form-control, .form-select');
    inputs.forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', () => {
            input.parentElement.classList.remove('focused');
        });
    });
    
    // Lazy loading
    const images = document.querySelectorAll('img[data-src]');
    const imageObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.removeAttribute('data-src');
                imageObserver.unobserve(img);
            }
        });
    });
    
    images.forEach(img => imageObserver.observe(img));
});

// Pencere boyutu değiştiğinde dropdown pozisyonlarını güncelle
window.addEventListener('resize', () => {
    const dropdowns = document.querySelectorAll('.dropdown-menu');
    dropdowns.forEach(dropdown => {
        dropdown.style.top = '';
        dropdown.style.bottom = '';
    });
});

document.addEventListener('DOMContentLoaded',()=>{
  const studyCtx=document.getElementById('studyChart');
  if(studyCtx && window.weekData){
    new Chart(studyCtx,{
      type:'bar',
      data:{labels:['Pzt','Sal','Çar','Per','Cum','Cmt','Paz'],datasets:[{label:'Dakika',data:window.weekData,backgroundColor:'#6c7cd2'}]},
      options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}
    });
  }
  const netCtx=document.getElementById('netChart');
  if(netCtx && window.netData){
    new Chart(netCtx,{
      type:'doughnut',
      data:{labels:['TYT','AYT'],datasets:[{data:window.netData,backgroundColor:['#28a745','#ffc107']} ]},
      options:{responsive:true,circumference:180,rotation:-90}
    });
  }
  if(window.AOS){AOS.init();}
}); 