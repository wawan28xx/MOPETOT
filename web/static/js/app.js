// Mobile Audit Tool - Frontend JS

// HTMX configuration
document.addEventListener('DOMContentLoaded', () => {
    // Initialize any HTMX extensions
    if (typeof htmx !== 'undefined') {
        htmx.config.defaultSwapStyle = 'innerHTML';
    }

    // Auto-dismiss search dropdown when clicking outside
    document.addEventListener('click', (e) => {
        const searchResults = document.getElementById('search-results');
        const searchInput = document.getElementById('global-search');
        if (searchResults && !searchResults.contains(e.target) && e.target !== searchInput) {
            searchResults.style.display = 'none';
        }
    });

    // Show search results
    const globalSearch = document.getElementById('global-search');
    if (globalSearch) {
        globalSearch.addEventListener('focus', () => {
            const results = document.getElementById('search-results');
            if (results && results.innerHTML.trim()) {
                results.style.display = 'block';
            }
        });
    }
});

// Format file size
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard');
    });
}

// Toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        padding: 12px 24px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text-primary);
        z-index: 1000;
        animation: fadeIn 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+U or Cmd+U to go to upload
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        window.location.href = '/upload';
    }
    // / to focus search
    if (e.key === '/' && !e.target.matches('input, textarea')) {
        e.preventDefault();
        const search = document.getElementById('global-search');
        if (search) search.focus();
    }
});
