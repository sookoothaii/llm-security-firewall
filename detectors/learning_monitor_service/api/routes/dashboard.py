"""
Dashboard Routes

HTML dashboard for monitoring.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Professionelles HTML Dashboard."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Learning Monitor Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: #1a1a1a; 
                color: #e0e0e0; 
                padding: 20px;
                line-height: 1.6;
            }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { 
                color: #4a9eff; 
                margin-bottom: 10px; 
                font-size: 28px;
                border-bottom: 2px solid #4a9eff;
                padding-bottom: 10px;
            }
            .timestamp {
                color: #888;
                font-size: 12px;
                margin-bottom: 20px;
            }
            .section {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                border: 1px solid #3a3a3a;
            }
            .section-title {
                color: #4a9eff;
                font-size: 20px;
                margin-bottom: 15px;
                font-weight: 600;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            th {
                background: #333;
                color: #fff;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid #4a9eff;
            }
            td {
                padding: 12px;
                border-bottom: 1px solid #3a3a3a;
            }
            tr:hover { background: #333; }
            .status-healthy { 
                color: #4caf50; 
                font-weight: 600;
            }
            .status-unhealthy { 
                color: #f44336; 
                font-weight: 600;
            }
            .metric {
                display: inline-block;
                background: #3a3a3a;
                padding: 8px 12px;
                border-radius: 4px;
                margin: 5px 5px 5px 0;
                font-weight: 600;
            }
            .metric-label {
                color: #aaa;
                font-size: 12px;
                display: block;
                margin-bottom: 4px;
            }
            .metric-value {
                color: #4a9eff;
                font-size: 18px;
            }
            .alert {
                padding: 12px;
                margin: 8px 0;
                border-radius: 4px;
                border-left: 4px solid;
            }
            .alert-critical {
                background: #3a1f1f;
                border-color: #f44336;
                color: #ff6b6b;
            }
            .alert-warning {
                background: #3a2f1f;
                border-color: #ff9800;
                color: #ffb74d;
            }
            .no-data {
                color: #888;
                font-style: italic;
                text-align: center;
                padding: 20px;
            }
            .badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 600;
            }
            .badge-enabled { background: #4caf50; color: #fff; }
            .badge-disabled { background: #666; color: #fff; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Learning Monitor Dashboard</h1>
            <div class="timestamp" id="timestamp">Lade...</div>
            
            <div class="section">
                <div class="section-title">Service Status</div>
                <div id="services-table"></div>
            </div>
            
            <div class="section">
                <div class="section-title">Alerts</div>
                <div id="alerts-container"></div>
            </div>
        </div>
        
        <script>
            const ws = new WebSocket('ws://localhost:8004/ws');
            
            ws.onopen = () => {
                console.log('WebSocket verbunden');
            };
            
            ws.onerror = (error) => {
                console.error('WebSocket Fehler:', error);
                document.getElementById('services-table').innerHTML = 
                    '<div class="no-data">Fehler: WebSocket-Verbindung fehlgeschlagen</div>';
            };
            
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                
                // Timestamp aktualisieren
                const timestamp = new Date(data.timestamp || Date.now()).toLocaleString('de-DE');
                document.getElementById('timestamp').textContent = `Letzte Aktualisierung: ${timestamp}`;
                
                // Services-Tabelle erstellen
                let servicesHtml = '';
                if (Object.keys(data.services || {}).length === 0) {
                    servicesHtml = '<div class="no-data">Keine Services gefunden</div>';
                } else {
                    servicesHtml = '<table><thead><tr>';
                    servicesHtml += '<th>Service</th>';
                    servicesHtml += '<th>Status</th>';
                    servicesHtml += '<th>Feedback</th>';
                    servicesHtml += '<th>Metriken</th>';
                    servicesHtml += '</tr></thead><tbody>';
                    
                    for (const [id, service] of Object.entries(data.services)) {
                        const statusClass = service.status === 'healthy' ? 'status-healthy' : 'status-unhealthy';
                        const statusText = service.status === 'healthy' ? 'HEALTHY' : 'UNHEALTHY';
                        
                        let feedbackHtml = '<span class="badge badge-disabled">Nicht verfügbar</span>';
                        let metricsHtml = '<span class="no-data">-</span>';
                        
                        if (service.feedback_enabled) {
                            feedbackHtml = '<span class="badge badge-enabled">Aktiv</span>';
                            
                            // Orchestrator Metriken
                            if (service.statistics && service.statistics.false_negatives_24h !== undefined) {
                                metricsHtml = '<div>';
                                metricsHtml += `<div class="metric"><span class="metric-label">False Negatives (24h)</span><span class="metric-value">${service.statistics.false_negatives_24h || 0}</span></div>`;
                                metricsHtml += `<div class="metric"><span class="metric-label">False Positives</span><span class="metric-value">${service.statistics.false_positives_total || 0}</span></div>`;
                                const optStatus = service.statistics.auto_optimization ? 'Enabled' : 'Disabled';
                                const optClass = service.statistics.auto_optimization ? 'badge-enabled' : 'badge-disabled';
                                metricsHtml += `<div class="metric"><span class="metric-label">Auto Optimization</span><span class="badge ${optClass}">${optStatus}</span></div>`;
                                metricsHtml += '</div>';
                            }
                            // Code Intent / Andere Metriken
                            else if (service.buffer_size !== undefined) {
                                metricsHtml = '<div>';
                                metricsHtml += `<div class="metric"><span class="metric-label">Buffer</span><span class="metric-value">${service.buffer_size}/${service.max_size || 'N/A'}</span></div>`;
                                if (service.online_learning && service.online_learning.running) {
                                    metricsHtml += `<div class="metric"><span class="metric-label">Updates</span><span class="metric-value">${service.online_learning.learner_stats?.updates || 0}</span></div>`;
                                    metricsHtml += `<div class="metric"><span class="metric-label">Loss</span><span class="metric-value">${(service.online_learning.learner_stats?.average_loss || 0).toFixed(4)}</span></div>`;
                                }
                                metricsHtml += '</div>';
                            }
                        }
                        
                        servicesHtml += '<tr>';
                        servicesHtml += `<td><strong>${service.service_name || id}</strong></td>`;
                        servicesHtml += `<td><span class="${statusClass}">${statusText}</span></td>`;
                        servicesHtml += `<td>${feedbackHtml}</td>`;
                        servicesHtml += `<td>${metricsHtml}</td>`;
                        servicesHtml += '</tr>';
                    }
                    
                    servicesHtml += '</tbody></table>';
                }
                
                document.getElementById('services-table').innerHTML = servicesHtml;
                
                // Alerts
                let alertsHtml = '';
                if (!data.alerts || data.alerts.length === 0) {
                    alertsHtml = '<div class="no-data">Keine Alerts</div>';
                } else {
                    data.alerts.forEach(alert => {
                        const alertClass = alert.severity === 'critical' ? 'alert-critical' : 'alert-warning';
                        alertsHtml += `<div class="alert ${alertClass}">`;
                        alertsHtml += `<strong>${alert.severity.toUpperCase()}</strong> [${alert.service}] ${alert.message}`;
                        if (alert.value !== undefined && alert.value !== null) {
                            alertsHtml += ` <span style="color: #888;">(Wert: ${alert.value})</span>`;
                        }
                        alertsHtml += '</div>';
                    });
                }
                
                document.getElementById('alerts-container').innerHTML = alertsHtml;
            };
        </script>
    </body>
    </html>
    """
    return html
