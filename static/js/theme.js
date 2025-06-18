// Tema değiştirme işlevselliği
class ThemeManager {
    constructor() {
        this.themeKey = 'theme';
        this.defaultTheme = 'light';
        this.html = document.documentElement;
        this.themeToggle = document.getElementById('theme-toggle');
        this.themeIcon = this.themeToggle?.querySelector('i');
        
        this.init();
    }
    
    init() {
        // Kaydedilmiş temayı yükle
        const savedTheme = localStorage.getItem(this.themeKey) || this.defaultTheme;
        this.setTheme(savedTheme);
        
        // Sistem temasını dinle
        this.listenToSystemTheme();
        
        // Tema değiştirme butonunu ayarla
        if (this.themeToggle) {
            this.themeToggle.addEventListener('click', () => this.toggleTheme());
        }
    }
    
    setTheme(theme) {
        // HTML data-theme özniteliğini güncelle
        this.html.setAttribute('data-theme', theme);
        
        // Tema ikonunu güncelle
        if (this.themeIcon) {
            this.themeIcon.className = theme === 'dark' ? 'bi bi-moon-fill' : 'bi bi-sun-fill';
        }
        
        // Temayı localStorage'a kaydet
        localStorage.setItem(this.themeKey, theme);
        
        // Özel tema değişikliği olayını tetikle
        this.dispatchThemeChangeEvent(theme);
    }
    
    toggleTheme() {
        const currentTheme = this.html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        // Tema geçiş animasyonu
        this.html.classList.add('theme-transition');
        setTimeout(() => this.html.classList.remove('theme-transition'), 300);
        
        this.setTheme(newTheme);
    }
    
    listenToSystemTheme() {
        // Sistem teması değişikliklerini dinle
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        
        const handleSystemThemeChange = (e) => {
            if (!localStorage.getItem(this.themeKey)) {
                this.setTheme(e.matches ? 'dark' : 'light');
            }
        };
        
        mediaQuery.addEventListener('change', handleSystemThemeChange);
        
        // İlk yükleme kontrolü
        if (!localStorage.getItem(this.themeKey)) {
            handleSystemThemeChange(mediaQuery);
        }
    }
    
    dispatchThemeChangeEvent(theme) {
        // Özel tema değişikliği olayını tetikle
        const event = new CustomEvent('themeChange', {
            detail: { theme }
        });
        document.dispatchEvent(event);
    }
}

// Tema yöneticisini başlat
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
    
    // Tema değişikliği olayını dinle
    document.addEventListener('themeChange', (e) => {
        const theme = e.detail.theme;
        
        // Grafikleri güncelle
        const charts = document.querySelectorAll('canvas');
        charts.forEach(canvas => {
            const chart = canvas.chart;
            if (chart) {
                const isDark = theme === 'dark';
                
                // Grafik renklerini güncelle
                chart.options.scales.x.grid.color = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
                chart.options.scales.y.grid.color = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
                chart.options.scales.x.ticks.color = isDark ? '#94a3b8' : '#64748b';
                chart.options.scales.y.ticks.color = isDark ? '#94a3b8' : '#64748b';
                
                chart.update();
            }
        });
    });

  const backToTop = document.getElementById("backToTop");
  if (backToTop) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 300) {
        backToTop.classList.add("show");
      } else {
        backToTop.classList.remove("show");
      }
    });

    backToTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
});

// CSS Animasyonu için stil ekle
const style = document.createElement("style");
style.textContent = `
    #themeToggle {
        transition: transform 0.5s ease;
    }
    #themeToggle.rotate {
        transform: rotate(360deg);
    }
    .bi {
        transition: all 0.3s ease;
    }
`;
document.head.appendChild(style);
