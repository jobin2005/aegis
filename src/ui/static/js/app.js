// src/ui/static/js/app.js
async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();
        const container = document.getElementById('alert-container');
        
        if (data.alerts && data.alerts.length > 0) {
            container.innerHTML = '';
            data.alerts.forEach(alert => {
                const severities = alert.severity || 'LOW';
                
                const card = document.createElement('div');
                card.className = `alert-card severity-${severities}`;
                
                card.innerHTML = `
                    <div class="alert-content">
                        <div class="alert-title">${alert.description || 'Unknown Alert'}</div>
                        <div class="alert-meta">
                            <span><strong>Time:</strong> ${new Date(alert.created_at).toLocaleTimeString() || 'N/A'}</span>
                            <span><strong>Engine:</strong> ${alert.alert_type}</span>
                            <span><strong>Target:</strong> ${alert.dst_ip || 'N/A'}</span>
                            <span><strong>Source:</strong> ${alert.src_ip || 'N/A'}</span>
                        </div>
                    </div>
                    <div>
                        <span class="badge badge-${severities}">${severities}</span>
                    </div>
                `;
                container.appendChild(card);
            });
        }
    } catch (error) {
        console.error("Error fetching alerts:", error);
    }
}

// Fetch immediately and poll every 2 seconds
fetchAlerts();
setInterval(fetchAlerts, 2000);
