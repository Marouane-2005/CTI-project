# Script PowerShell pour creer l'architecture Dashboard CTI
Write-Host "Creation de l'architecture Dashboard CTI..." -ForegroundColor Green

# Créer tous les dossiers
$folders = @(
    "dashboard",
    "dashboard\static",
    "dashboard\static\css",
    "dashboard\static\js", 
    "dashboard\static\assets",
    "dashboard\templates",
    "dashboard\components",
    "dashboard\views",
    "monitoring",
    "monitoring\alerts",
    "monitoring\metrics",
    "monitoring\watchdog",
    "reports",
    "reports\generators",
    "reports\templates",
    "reports\exporters",
    "docker\dashboard",
    "docker\redis",
    "docker\output\dashboard_reports",
    "docker\output\dashboard_reports\daily",
    "docker\output\dashboard_reports\weekly",
    "docker\output\dashboard_reports\monthly"
)

foreach ($folder in $folders) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    Write-Host "OK Cree: $folder" -ForegroundColor Gray
}

# Créer tous les fichiers
$files = @(
    # API files
    "api\dashboard_api.py",
    "api\reports_api.py",
    "api\alerts_api.py",
    
    # Config files
    "config\dashboard_config.json",
    "config\alerts_config.json",
    "config\reports_config.json",
    
    # Dashboard files
    "dashboard\__init__.py",
    "dashboard\app.py",
    
    # Dashboard static files
    "dashboard\static\css\dashboard.css",
    "dashboard\static\css\reports.css",
    "dashboard\static\js\dashboard.js",
    "dashboard\static\js\charts.js",
    "dashboard\static\js\alerts.js",
    "dashboard\static\js\reports.js",
    
    # Dashboard templates
    "dashboard\templates\base.html",
    "dashboard\templates\dashboard.html",
    "dashboard\templates\reports.html",
    "dashboard\templates\alerts.html",
    "dashboard\templates\analytics.html",
    
    # Dashboard components
    "dashboard\components\__init__.py",
    "dashboard\components\charts.py",
    "dashboard\components\widgets.py",
    "dashboard\components\tables.py",
    "dashboard\components\alerts.py",
    
    # Dashboard views
    "dashboard\views\__init__.py",
    "dashboard\views\dashboard_views.py",
    "dashboard\views\analytics_views.py",
    "dashboard\views\reports_views.py",
    "dashboard\views\alerts_views.py",
    
    # Monitoring files
    "monitoring\__init__.py",
    "monitoring\alerts\__init__.py",
    "monitoring\alerts\alert_engine.py",
    "monitoring\alerts\notification_handler.py",
    "monitoring\alerts\alert_rules.py",
    "monitoring\metrics\__init__.py",
    "monitoring\metrics\collector_metrics.py",
    "monitoring\metrics\vulnerability_metrics.py",
    "monitoring\metrics\threat_metrics.py",
    "monitoring\watchdog\__init__.py",
    "monitoring\watchdog\service_monitor.py",
    "monitoring\watchdog\health_checker.py",
    
    # Reports files
    "reports\__init__.py",
    "reports\generators\__init__.py",
    "reports\generators\daily_report.py",
    "reports\generators\weekly_report.py",
    "reports\generators\monthly_report.py",
    "reports\generators\executive_summary.py",
    "reports\templates\daily_template.html",
    "reports\templates\weekly_template.html",
    "reports\templates\monthly_template.html",
    "reports\templates\executive_template.html",
    "reports\exporters\__init__.py",
    "reports\exporters\pdf_exporter.py",
    "reports\exporters\excel_exporter.py",
    "reports\exporters\email_sender.py",
    
    # Scripts utilitaires
    "scripts\generators\dashboard_report_generator.py",
    "scripts\generators\alert_generator.py",
    "scripts\pipeline\dashboard_scheduler.py",
    "scripts\utils\dashboard_utils.py",
    "scripts\utils\report_utils.py",
    "scripts\analyzers\trend_analyzer.py",
    "scripts\analyzers\statistics_analyzer.py",
    
    # Docker files
    "docker\dashboard\Dockerfile",
    "docker\dashboard\nginx.conf",
    "docker\redis\redis.conf",
    
    # Main files
    "docker-compose-dashboard.yml",
    "dashboard_main.py",
    "requirements-dashboard.txt",
    ".github\workflows\dashboard-deploy.yml"
)

foreach ($file in $files) {
    New-Item -ItemType File -Force -Path $file | Out-Null
    Write-Host "OK Cree: $file" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Structure creee avec succes!" -ForegroundColor Green
Write-Host ""
Write-Host "Nouveaux modules:" -ForegroundColor Yellow
Write-Host "   - dashboard\ (Interface web)" -ForegroundColor White
Write-Host "   - monitoring\ (Alertes et metriques)" -ForegroundColor White
Write-Host "   - reports\ (Generation de rapports)" -ForegroundColor White
Write-Host ""
Write-Host "Pret pour la configuration!" -ForegroundColor Cyan