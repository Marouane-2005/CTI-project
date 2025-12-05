""" dashboard/backend/report_generator.py"""


import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import os
import uuid

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, data_processor, db_connection=None):
      
        try:
          from reportlab.lib.pagesizes import A4
          from reportlab.platypus import SimpleDocTemplate
          from jinja2 import Template
        except ImportError as e:
           logger.error(f"❌ Dépendances manquantes dans ReportGenerator: {e}")
           raise ImportError(f"Dépendances requises manquantes: {e}")
        self.data_processor = data_processor
        self.db_connection = db_connection
        self.reports_dir = "reports/"
        self.templates_dir = "templates/"
        
        # ✅ CORRECTION 1: Créer les dossiers avec gestion d'erreur
        try:
            os.makedirs(self.reports_dir, exist_ok=True)
            os.makedirs(self.templates_dir, exist_ok=True)
            logger.info(f"✅ Dossiers créés: {self.reports_dir}, {self.templates_dir}")
        except Exception as e:
            logger.error(f"❌ Erreur création dossiers: {e}")
            # Utiliser un dossier temporaire en fallback
            import tempfile
            self.reports_dir = tempfile.gettempdir() + "/cti_reports/"
            os.makedirs(self.reports_dir, exist_ok=True)
        
        # Styles pour les rapports
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.logo_path = None
        self._setup_logo_path() 
       
    def _setup_custom_styles(self):
     try:
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib import colors
        
        # Vérifier que les styles de base existent
        if not hasattr(self, 'styles') or not self.styles:
            from reportlab.lib.styles import getSampleStyleSheet
            self.styles = getSampleStyleSheet()
        
        # Ajouter des styles personnalisés avec gestion d'erreur
        try:
            self.styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=18,
                textColor=colors.darkblue,
                alignment=1,  # Center
                spaceAfter=20
            ))
        except Exception as style_error:
            logger.warning(f"⚠️ Impossible d'ajouter style CustomTitle: {style_error}")
        
        logger.info("✅ Styles PDF configurés")
        
     except Exception as e:
        logger.error(f"❌ Erreur configuration styles: {e}")
        # Utiliser les styles par défaut
        try:
            from reportlab.lib.styles import getSampleStyleSheet
            self.styles = getSampleStyleSheet()
        except Exception:
            self.styles = None

    
    def _setup_logo_path(self):
      try:
        # Chemin relatif depuis le backend vers le logo
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'src', 'assets', 'images', 'symolia-logo.png'),
            os.path.join('Dashboard', 'frontend', 'src', 'assets', 'images', 'symolia-logo.png'),
            os.path.join('frontend', 'src', 'assets', 'images', 'symolia-logo.png'),
            'symolia-logo.png'  # Si copié dans le dossier reports
        ]
        
        for path in possible_paths:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                self.logo_path = abs_path
                logger.info(f"✅ Logo trouvé: {abs_path}")
                break
        
        if not self.logo_path:
            logger.warning("⚠️ Logo Symolia non trouvé - rapport sans logo")
            
      except Exception as e:
        logger.error(f"❌ Erreur configuration logo: {e}")
        self.logo_path = None

    def generate_daily_report(self, date: datetime = None) -> Dict[str, Any]:
     if date is None:
        date = datetime.now()
    
     report_id = f"daily_{date.strftime('%Y%m%d')}_{str(uuid.uuid4())[:8]}"
    
     try:
        logger.info(f"🔄 Génération rapport quotidien: {report_id}")
        
        # ✅ CORRECTION: Gestion d'erreur pour collecte de données
        alerts_data = self.data_processor.get_detailed_alerts_for_report(hours=24)
        
        try:
            if hasattr(self.data_processor, 'get_live_threats'):
                threats_data = self.data_processor.get_live_threats(hours=24)
            if hasattr(self.data_processor, 'get_alerts_data'):
                alerts_data = self.data_processor.get_alerts_data()
            if hasattr(self.data_processor, 'get_dashboard_overview'):
                stats_data = self.data_processor.get_dashboard_overview()
        except Exception as data_error:
            logger.warning(f"⚠️ Erreur collecte données: {data_error}")
        
        # Données du rapport
        report_data = {
            'id': report_id,
            'title': f'Rapport Quotidien CTI - {date.strftime("%d/%m/%Y")}',
            'type': 'daily',
            'period': 'Dernières 24 heures',
            'generated_at': datetime.now().isoformat(),
            'executive_summary': self._generate_daily_executive_summary(threats_data, alerts_data),
            'key_metrics': {
                'threats_detected': len(threats_data.get('threats', [])),
                'alerts_generated': len(alerts_data.get('alerts', [])),
                'iocs_processed': stats_data.get('total_indicators', 0),
                'risk_level': self._calculate_daily_risk_level(threats_data, alerts_data)
            },
            'top_threats': self._get_top_daily_threats(threats_data),
            
            # ✅ AJOUT: Section détaillée des alertes
            'detailed_alerts_section': self._generate_detailed_alerts_section(alerts_data),
            
            'alert_summary': self._summarize_daily_alerts(alerts_data),
            'recommendations': self._generate_daily_recommendations(threats_data, alerts_data)
        }
        
        # ✅ CORRECTION: Génération des fichiers avec gestion d'erreur
        pdf_path = None
        html_path = None
        errors = []
        
        try:
            pdf_path = self._generate_pdf_report(report_data)
            if pdf_path:
                logger.info(f"✅ PDF généré: {pdf_path}")
            else:
                errors.append("Erreur génération PDF")
        except Exception as pdf_error:
            logger.error(f"❌ Erreur génération PDF: {pdf_error}")
            errors.append(f"PDF: {str(pdf_error)}")
        
        try:
            html_path = self._generate_html_report(report_data)
            if html_path:
                logger.info(f"✅ HTML généré: {html_path}")
            else:
                errors.append("Erreur génération HTML")
        except Exception as html_error:
            logger.error(f"❌ Erreur génération HTML: {html_error}")
            errors.append(f"HTML: {str(html_error)}")
        
        # ✅ CORRECTION: Sauvegarder les métadonnées même en cas d'erreur partielle
        try:
            if pdf_path or html_path:
                self._save_report_metadata(report_data, pdf_path, html_path)
        except Exception as save_error:
            logger.warning(f"⚠️ Erreur sauvegarde métadonnées: {save_error}")
            errors.append(f"Métadonnées: {str(save_error)}")
        
        # ✅ CORRECTION: Retour structuré
        status = 'completed' if (pdf_path and html_path) else ('partial' if (pdf_path or html_path) else 'error')
        
        result = {
            'status': status,
            'report_id': report_id,
            'pdf_path': pdf_path,
            'html_path': html_path,
            'executive_summary': report_data['executive_summary'],
            'key_metrics': report_data['key_metrics'],
            'top_threats': report_data['top_threats'],
            'timestamp': datetime.now().isoformat()
        }
        
        if errors:
            result['errors'] = errors
            result['warnings'] = errors
            
        return result
        
     except Exception as e:
        logger.error(f"❌ Erreur génération rapport quotidien: {e}")
        return {
            'status': 'error',
            'report_id': report_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
    

    def _generate_pdf_report(self, report_data: Dict) -> str:
     filename = f"{report_data['id']}.pdf"
     filepath = os.path.join(self.reports_dir, filename)
    
     try:
        # ✅ MODIFICATION: Ajout du logo avant le titre
        if self.logo_path and os.path.exists(self.logo_path):
            try:
                from reportlab.platypus import Image
                from reportlab.lib.units import inch
                
                # Créer l'image du logo
                logo = Image(self.logo_path, width=2*inch, height=0.8*inch)
                story.append(logo)
                story.append(Spacer(1, 10))
                
                logger.info(f"✅ Logo ajouté au PDF: {self.logo_path}")
                
            except Exception as logo_error:
                logger.warning(f"⚠️ Erreur ajout logo PDF: {logo_error}")
        
        # 1. TITRE PRINCIPAL (code existant inchangé)
        if hasattr(self, 'styles') and 'CustomTitle' in self.styles:
            title_style = self.styles['CustomTitle']
        else:
            title_style = self.styles['Heading1'] if hasattr(self, 'styles') else None
        
        logger.info(f"🔄 Création PDF détaillé: {filepath}")
        
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir, exist_ok=True)
            logger.info(f"📁 Dossier créé: {self.reports_dir}")
        
        # Vérifier les permissions d'écriture
        if not os.access(self.reports_dir, os.W_OK):
            logger.error(f"❌ Pas de permission d'écriture: {self.reports_dir}")
            return None
        
        # Vérifier les dépendances reportlab
        try:
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.units import inch
        except ImportError as e:
            logger.error(f"❌ Dépendances reportlab manquantes: {e}")
            raise Exception("Bibliothèques PDF non installées")
        
        # Créer le document PDF
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        try:
            # 1. TITRE PRINCIPAL
            if hasattr(self, 'styles') and 'CustomTitle' in self.styles:
                title_style = self.styles['CustomTitle']
            else:
                title_style = self.styles['Heading1'] if hasattr(self, 'styles') else None
            
            if title_style:
                title = Paragraph(
                    self._sanitize_text(report_data.get('title', 'Rapport CTI')), 
                    title_style
                )
                story.append(title)
                story.append(Spacer(1, 20))
            
            # 2. INFORMATIONS GÉNÉRALES
            period = self._sanitize_text(report_data.get('period', 'N/A'))
            generated_time = datetime.now().strftime('%d/%m/%Y à %H:%M')
            
            info_text = f"<b>Période:</b> {period}<br/>"
            info_text += f"<b>Généré le:</b> {generated_time}<br/>"
            info_text += f"<b>Type de rapport:</b> {report_data.get('type', 'quotidien').title()}<br/>"
            
            normal_style = self.styles.get('Normal') if hasattr(self, 'styles') else None
            heading2_style = self.styles.get('Heading2') if hasattr(self, 'styles') else normal_style
            heading3_style = self.styles.get('Heading3') if hasattr(self, 'styles') else normal_style
            
            if normal_style:
                story.append(Paragraph(info_text, normal_style))
                story.append(Spacer(1, 20))
            
            # 3. RÉSUMÉ EXÉCUTIF
            if normal_style:
                story.append(Paragraph("Résumé Exécutif", heading2_style))
                executive_summary = self._sanitize_text(
                    report_data.get('executive_summary', 'Aucun résumé disponible')
                )
                story.append(Paragraph(executive_summary, normal_style))
                story.append(Spacer(1, 20))
            
            # 4. MÉTRIQUES CLÉS
            key_metrics = report_data.get('key_metrics', {})
            if key_metrics and normal_style:
                story.append(Paragraph("Métriques Clés", heading2_style))
                
                # Créer un tableau pour les métriques
                metrics_data = []
                for key, value in key_metrics.items():
                    metric_name = self._format_metric_name(key)
                    metric_value = str(value) if value is not None else 'N/A'
                    metrics_data.append([metric_name, metric_value])
                
                if metrics_data:
                    metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
                    metrics_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ]))
                    story.append(metrics_table)
                    story.append(Spacer(1, 20))
            
            # 5. ANALYSE DÉTAILLÉE DES ALERTES
            detailed_alerts = report_data.get('detailed_alerts_section', {})
            if detailed_alerts and normal_style:
                story.append(Paragraph("Analyse Détaillée des Alertes", heading2_style))
                story.append(Spacer(1, 10))
                
                # 5.1 Statistiques des alertes
                alert_stats = detailed_alerts.get('severity_distribution', {})
                total_alerts = detailed_alerts.get('total_alerts', 0)
                
                if total_alerts > 0:
                    stats_text = f"<b>Total des alertes analysées:</b> {total_alerts}<br/><br/>"
                    stats_text += "<b>Répartition par niveau de criticité:</b><br/>"
                    
                    for level in ['critical', 'high', 'medium', 'low']:
                        count = alert_stats.get(level, 0)
                        if count > 0:
                            level_fr = self._translate_level(level)
                            percentage = (count / total_alerts) * 100
                            stats_text += f"• {level_fr}: {count} ({percentage:.1f}%)<br/>"
                    
                    story.append(Paragraph(stats_text, normal_style))
                    story.append(Spacer(1, 15))
                    
                    # 5.2 Répartition par source
                    source_distribution = detailed_alerts.get('source_distribution', {})
                    if source_distribution:
                        source_text = "<b>Répartition par source:</b><br/>"
                        for source, count in source_distribution.items():
                            percentage = (count / total_alerts) * 100
                            source_text += f"• {source}: {count} ({percentage:.1f}%)<br/>"
                        
                        story.append(Paragraph(source_text, normal_style))
                        story.append(Spacer(1, 15))
                
                # 5.3 Détails des alertes individuelles
                alert_details = detailed_alerts.get('alert_details', [])
                if alert_details:
                    story.append(Paragraph("Alertes Détectées (Top 10)", heading3_style))
                    story.append(Spacer(1, 10))
                    
                    for i, alert in enumerate(alert_details[:10]):
                        # Titre de l'alerte avec numéro
                        alert_title = f"Alerte #{i+1}: {alert.get('title', 'Sans titre')}"
                        story.append(Paragraph(f"<b>{self._sanitize_text(alert_title)}</b>", heading3_style))
                        
                        # Informations de base
                        alert_info = f"<b>Niveau:</b> {self._translate_level(alert.get('level', 'medium'))}<br/>"
                        alert_info += f"<b>Source:</b> {alert.get('source', 'N/A')}<br/>"
                        alert_info += f"<b>Timestamp:</b> {self._format_timestamp(alert.get('timestamp'))}<br/>"
                        alert_info += f"<b>Statut:</b> {'Acquittée' if alert.get('acknowledged', False) else 'Non acquittée'}<br/>"
                        alert_info += f"<b>Description:</b> {self._sanitize_text(alert.get('description', 'N/A'))}<br/>"
                        
                        # Détails techniques
                        tech_details = alert.get('technical_details', {})
                        if tech_details and tech_details.get('indicator_value') != 'N/A':
                            alert_info += f"<b>Indicateur détecté:</b> {tech_details.get('indicator_value')} "
                            alert_info += f"({tech_details.get('indicator_type', 'inconnu')})<br/>"
                            
                            confidence = tech_details.get('confidence_level', 0)
                            if confidence > 0:
                                alert_info += f"<b>Niveau de confiance:</b> {confidence}%<br/>"
                        
                        # Analyse MITRE ATT&CK
                        mitre_analysis = alert.get('mitre_analysis', {})
                        techniques = mitre_analysis.get('techniques', [])
                        if techniques:
                            alert_info += f"<b>Techniques MITRE ATT&amp;CK:</b> {', '.join(techniques[:5])}<br/>"
                            
                            tactics = mitre_analysis.get('tactics', [])
                            if tactics:
                                alert_info += f"<b>Tactiques:</b> {', '.join(tactics[:3])}<br/>"
                        
                        # Score de risque calculé
                        risk_info = alert.get('calculated_risk', {})
                        if risk_info and risk_info.get('calculated_score'):
                            score = risk_info['calculated_score']
                            category = risk_info.get('risk_category', 'N/A')
                            alert_info += f"<b>Score de risque calculé:</b> {score}/10 (Catégorie: {category})<br/>"
                        
                        story.append(Paragraph(alert_info, normal_style))
                        
                        # Actions recommandées
                        actions = alert.get('recommended_actions', [])
                        if actions:
                            actions_text = "<b>Actions recommandées:</b><br/>"
                            for j, action in enumerate(actions[:4], 1):
                                actions_text += f"  {j}. {self._sanitize_text(action)}<br/>"
                            
                            story.append(Paragraph(actions_text, normal_style))
                        
                        story.append(Spacer(1, 15))
                        
                        # Ajouter une ligne de séparation
                        if i < len(alert_details[:10]) - 1:
                            separator = Paragraph("─" * 80, normal_style)
                            story.append(separator)
                            story.append(Spacer(1, 10))
                
                # 5.4 Analyse des tendances
                risk_analysis = detailed_alerts.get('risk_analysis', '')
                if risk_analysis:
                    story.append(Paragraph("Analyse des Tendances et Patterns", heading3_style))
                    story.append(Paragraph(self._sanitize_text(risk_analysis), normal_style))
                    story.append(Spacer(1, 15))
                
                # 5.5 Recommandations spécifiques
                alert_recommendations = detailed_alerts.get('recommendations', [])
                if alert_recommendations:
                    story.append(Paragraph("Recommandations Spécifiques", heading3_style))
                    rec_text = ""
                    for i, rec in enumerate(alert_recommendations, 1):
                        rec_text += f"{i}. {self._sanitize_text(rec)}<br/>"
                    
                    story.append(Paragraph(rec_text, normal_style))
                    story.append(Spacer(1, 20))
            else:
                # Section par défaut si pas d'alertes détaillées
                story.append(Paragraph("Analyse des Alertes", heading2_style))
                story.append(Paragraph("Aucune alerte détectée pendant cette période.", normal_style))
                story.append(Spacer(1, 20))
            
            # 6. PRINCIPALES MENACES
            top_threats = report_data.get('top_threats', [])
            if top_threats and normal_style:
                story.append(Paragraph("Principales Menaces Détectées", heading2_style))
                
                for i, threat in enumerate(top_threats[:5], 1):
                    threat_text = f"<b>{i}. {threat.get('name', 'Menace inconnue')}</b><br/>"
                    threat_text += f"Score de risque: {threat.get('risk_score', 0)}/10<br/>"
                    threat_text += f"Occurrences: {threat.get('count', 1)}<br/>"
                    story.append(Paragraph(threat_text, normal_style))
                    story.append(Spacer(1, 10))
                
                story.append(Spacer(1, 15))
            
            # 7. RECOMMANDATIONS GÉNÉRALES
            recommendations = report_data.get('recommendations', [])
            if recommendations and normal_style:
                story.append(Paragraph("Recommandations Générales", heading2_style))
                
                rec_text = ""
                for i, rec in enumerate(recommendations, 1):
                    rec_text += f"{i}. {self._sanitize_text(rec)}<br/>"
                
                story.append(Paragraph(rec_text, normal_style))
                story.append(Spacer(1, 20))
            
            # 8. FOOTER/INFORMATIONS TECHNIQUES
            footer_text = f"<br/><br/>──────────────────────────────────────<br/>"
            footer_text += f"<b>Rapport généré automatiquement</b><br/>"
            footer_text += f"ID du rapport: {report_data.get('id', 'N/A')}<br/>"
            footer_text += f"Version du système: CTI Dashboard v1.0<br/>"
            footer_text += f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}<br/>"
            
            if normal_style:
                story.append(Paragraph(footer_text, normal_style))
            
        except Exception as content_error:
            logger.error(f"❌ Erreur création contenu PDF: {content_error}")
            # Contenu minimal de fallback
            story = []
            if hasattr(self, 'styles') and self.styles.get('Normal'):
                story.append(Paragraph("Rapport CTI - Erreur de génération détaillée", self.styles['Normal']))
                story.append(Paragraph(f"Erreur: {str(content_error)}", self.styles['Normal']))
                
                # Au moins afficher les métriques de base
                if key_metrics:
                    story.append(Paragraph("Métriques disponibles:", self.styles['Normal']))
                    for key, value in key_metrics.items():
                        story.append(Paragraph(f"{key}: {value}", self.styles['Normal']))
        
        # Contenu minimal garanti
        if not story:
            story.append(Paragraph("Rapport CTI - Erreur critique"))
        
        # Build du PDF
        try:
            doc.build(story)
        except Exception as build_error:
            logger.error(f"❌ Erreur build PDF: {build_error}")
            raise Exception(f"Erreur construction PDF: {str(build_error)}")
        
        # Vérification du fichier généré
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            if file_size > 1000:  # Au moins 1KB pour un rapport détaillé
                logger.info(f"✅ PDF détaillé généré: {filepath} ({file_size} bytes)")
                return filepath
            else:
                logger.error(f"❌ PDF généré mais trop petit: {file_size} bytes")
                return None
        else:
            logger.error(f"❌ Fichier PDF non créé: {filepath}")
            return None
        
     except Exception as e:
        logger.error(f"❌ Erreur génération PDF détaillé: {e}")
        return None
    
    # ✅ CORRECTION 4: Ajouter ces méthodes à la fin de votre ReportGenerator class

    def generate_weekly_report(self, start_date: datetime = None) -> Dict[str, Any]:
        """Génère le rapport hebdomadaire"""
        if start_date is None:
            start_date = datetime.now() - timedelta(days=7)
        
        report_id = f"weekly_{start_date.strftime('%Y%m%d')}_{str(uuid.uuid4())[:8]}"
        
        try:
            logger.info(f"🔄 Génération rapport hebdomadaire: {report_id}")
            
            # Collecter les données de la semaine
            try:
                threats_data = self.data_processor.get_live_threats(hours=24*7)  # 7 jours
                alerts_data = self.data_processor.get_alerts_data()
                stats_data = self.data_processor.get_dashboard_overview()
            except Exception as data_error:
                logger.warning(f"⚠️ Erreur collecte données hebdo: {data_error}")
                threats_data = {'threats': [], 'total': 0}
                alerts_data = {'alerts': [], 'total': 0}
                stats_data = {'total_indicators': 0, 'status': 'mock'}
            
            # Données du rapport hebdomadaire
            report_data = {
                'id': report_id,
                'title': f'Rapport Hebdomadaire CTI - Semaine du {start_date.strftime("%d/%m/%Y")}',
                'type': 'weekly',
                'period': 'Derniers 7 jours',
                'generated_at': datetime.now().isoformat(),
                'executive_summary': self._generate_weekly_executive_summary(threats_data, alerts_data),
                'key_metrics': {
                    'threats_detected': len(threats_data.get('threats', [])),
                    'alerts_generated': len(alerts_data.get('alerts', [])),
                    'iocs_processed': stats_data.get('total_indicators', 0),
                    'risk_level': self._calculate_daily_risk_level(threats_data, alerts_data)  # Réutiliser
                },
                'top_threats': self._get_top_daily_threats(threats_data),  # Réutiliser
                'alert_summary': self._summarize_daily_alerts(alerts_data),  # Réutiliser
                'recommendations': self._generate_weekly_recommendations(threats_data, alerts_data)
            }
            
            # Génération des fichiers
            pdf_path = None
            html_path = None
            
            try:
                pdf_path = self._generate_pdf_report(report_data)
                logger.info(f"✅ PDF hebdo généré: {pdf_path}")
            except Exception as pdf_error:
                logger.error(f"❌ Erreur génération PDF hebdo: {pdf_error}")
            
            try:
                html_path = self._generate_html_report(report_data)
                logger.info(f"✅ HTML hebdo généré: {html_path}")
            except Exception as html_error:
                logger.error(f"❌ Erreur génération HTML hebdo: {html_error}")
            
            return {
                'report_id': report_id,
                'status': 'completed' if (pdf_path and html_path) else 'partial',
                'pdf_path': pdf_path,
                'html_path': html_path,
                'executive_summary': report_data['executive_summary'],
                'key_metrics': report_data['key_metrics'],
                'warnings': [] if (pdf_path and html_path) else ['Erreur génération fichiers']
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur génération rapport hebdomadaire: {e}")
            return {
                'report_id': report_id,
                'status': 'error',
                'error': str(e)
            }

    def _generate_weekly_executive_summary(self, threats_data: Dict, alerts_data: Dict) -> str:
        """Génère le résumé exécutif hebdomadaire"""
        try:
            threats_count = len(threats_data.get('threats', []))
            alerts_count = len(alerts_data.get('alerts', []))
            
            if threats_count == 0 and alerts_count == 0:
                return "Semaine calme avec une activité malveillante minimale. Surveillance normale maintenue."
            
            summary = f"Au cours des 7 derniers jours, {threats_count} menace(s) détectée(s) "
            summary += f"avec {alerts_count} alerte(s) générée(s). "
            
            avg_daily = alerts_count / 7
            if avg_daily > 3:
                summary += "Activité soutenue nécessitant une attention particulière."
            elif avg_daily > 1:
                summary += "Niveau d'activité normal pour la période."
            else:
                summary += "Activité faible, surveillance de routine suffisante."
            
            return summary
        except Exception as e:
            logger.error(f"Erreur résumé hebdo: {e}")
            return "Erreur génération résumé hebdomadaire."

    def _generate_weekly_recommendations(self, threats_data: Dict, alerts_data: Dict) -> List[str]:
      try:
        recommendations = []
        
        threats_count = len(threats_data.get('threats', []))
        alerts_count = len(alerts_data.get('alerts', []))
        
        if alerts_count > 20:  # Plus de 20 alertes par semaine
            recommendations.append("Analyser les tendances d'alertes pour identifier les patterns récurrents")
            recommendations.append("Réviser les seuils de détection pour optimiser la précision")
        
        if threats_count > 10:
            recommendations.append("Effectuer une revue approfondie des IOCs les plus critiques")
            recommendations.append("Renforcer la corrélation avec les feeds de threat intelligence")
        
        # Recommandations générales
        recommendations.append("Planifier la revue hebdomadaire de sécurité avec l'équipe")
        recommendations.append("Mettre à jour la documentation des procédures de réponse")
        
        if not recommendations:
            recommendations.append("Maintenir les procédures de surveillance actuelles")
        
        return recommendations[:4]  # Limiter à 4 recommandations
        
      except Exception as e:
        logger.error(f"Erreur recommandations hebdo: {e}")
        return ["Erreur génération recommandations hebdomadaires"]

    def _generate_html_report(self, report_data: Dict) -> str:
     try:
        html_filename = f"{report_data['id']}.html"
        html_path = os.path.join(self.reports_dir, html_filename)
        
        # Template HTML enrichi avec styles CSS modernes
        html_template = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <title>{{ title }}</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 40px; 
            background-color: #f8f9fa;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header { 
            color: #2c5aa0; 
            border-bottom: 3px solid #2c5aa0; 
            padding-bottom: 15px; 
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.2em;
        }
        .report-info {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            border-left: 5px solid #2196f3;
        }
        .section {
            margin-bottom: 35px;
        }
        .section h2 {
            color: #1976d2;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }
        .section h3 {
            color: #424242;
            margin-bottom: 15px;
        }
        
        /* Styles pour les alertes */
        .alerts-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .severity-stat {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        .severity-critical { background: linear-gradient(135deg, #d32f2f, #f44336); }
        .severity-high { background: linear-gradient(135deg, #f57c00, #ff9800); }
        .severity-medium { background: linear-gradient(135deg, #fbc02d, #ffeb3b); color: #333; }
        .severity-low { background: linear-gradient(135deg, #388e3c, #4caf50); }
        
        .alert-detail { 
            background: white;
            border: 1px solid #e0e0e0;
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alert-detail.alert-critical { border-left: 5px solid #d32f2f; }
        .alert-detail.alert-high { border-left: 5px solid #f57c00; }
        .alert-detail.alert-medium { border-left: 5px solid #fbc02d; }
        .alert-detail.alert-low { border-left: 5px solid #388e3c; }
        
        .alert-detail h4 {
            margin: 0 0 10px 0;
            color: #1976d2;
            font-size: 1.2em;
        }
        .alert-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #666;
        }
        .alert-meta span {
            background: #f0f0f0;
            padding: 5px 10px;
            border-radius: 4px;
        }
        .technical-info, .mitre-info {
            background: #e8f5e8;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 3px solid #4caf50;
        }
        .mitre-info {
            background: #fff3e0;
            border-left: 3px solid #ff9800;
        }
        .recommendations {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border-left: 3px solid #2196f3;
        }
        .recommendations ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 5px 0;
        }
        
        .threat { 
            background: #ffebee;
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 6px;
            border-left: 4px solid #d63031; 
        }
        .threat h4 {
            margin: 0 0 8px 0;
            color: #c62828;
        }
        .recommendation { 
            background: #f0f8ff; 
            padding: 12px 15px; 
            margin: 8px 0; 
            border-radius: 6px;
            border-left: 4px solid #0984e3; 
        }
        
        .logo-container {
            text-align: left;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e0e0e0;
        }
        .logo {
            max-width: 200px;
            height: auto;
            max-height: 80px;
        }
        .header-with-logo {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .header-with-logo .logo-container {
            border: none;
            margin: 0;
            padding: 0;
        }
        .header-with-logo h1 {
            margin: 0;
            flex-grow: 1;
            text-align: center;
        }
        .risk-analysis {
            background: #fff8e1;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #ffc107;
            margin: 20px 0;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            body { padding: 20px; }
            .container { padding: 20px; }
            .alerts-summary { grid-template-columns: 1fr; }
            .alert-meta { flex-direction: column; gap: 8px; }
        }
        
        /* Print styles */
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .alert-detail { break-inside: avoid; }
        }
        @media (max-width: 768px) {
            .header-with-logo {
                flex-direction: column;
                text-align: center;
            }
            .header-with-logo .logo-container {
                margin-bottom: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- ✅ AJOUT: Section logo + header -->
        {% if logo_base64 %}
        <div class="header-with-logo">
            <div class="logo-container">
                <img src="data:image/png;base64,{{ logo_base64 }}" alt="Logo Symolia" class="logo">
            </div>
            <h1 style="color: #2c5aa0;">{{ title }}</h1>
            <div style="width: 200px;"></div> <!-- Spacer pour équilibrer -->
        </div>
        {% else %}
        <div class="header">
            <h1>{{ title }}</h1>
        </div>
        {% endif %}
        
        <!-- Section détaillée des alertes -->
        {% if detailed_alerts_section and detailed_alerts_section.total_alerts > 0 %}
        <div class="section">
            <h2>🚨 Analyse Détaillée des Alertes</h2>
            
            <!-- Statistiques des alertes -->
            <div class="alerts-summary">
                {% for level, count in detailed_alerts_section.severity_distribution.items() %}
                    {% if count > 0 %}
                    <div class="severity-stat severity-{{ level }}">
                        <div>{{ translate_level(level) }}</div>
                        <div style="font-size: 1.5em;">{{ count }}</div>
                    </div>
                    {% endif %}
                {% endfor %}
            </div>
            
            {% if detailed_alerts_section.unacknowledged_count > 0 %}
            <div style="background: #ffebee; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #f44336;">
                <strong>⚠️ Attention:</strong> {{ detailed_alerts_section.unacknowledged_count }} alerte(s) non acquittée(s) nécessitent une attention immédiate.
            </div>
            {% endif %}
            
            <!-- Détails des alertes individuelles -->
            <h3>🔍 Détails des Alertes (Top 10)</h3>
            {% for alert in detailed_alerts_section.alert_details[:10] %}
            <div class="alert-detail alert-{{ alert.level }}">
                <h4>{{ alert.title }}</h4>
                <div class="alert-meta">
                    <span><strong>Niveau:</strong> {{ translate_level(alert.level) }}</span>
                    <span><strong>Source:</strong> {{ alert.source }}</span>
                    <span><strong>Date:</strong> {{ format_timestamp(alert.timestamp) }}</span>
                    <span><strong>Statut:</strong> {{ "✅ Acquittée" if alert.acknowledged else "⏳ En attente" }}</span>
                </div>
                
                <p><strong>Description:</strong> {{ clean_description(alert.description) }}</p>
                
                {% if alert.technical_details and alert.technical_details.indicator_value != 'N/A' %}
                <div class="technical-info">
                    <strong>🎯 Indicateur détecté:</strong> 
                    <code>{{ alert.technical_details.indicator_value }}</code> 
                    ({{ alert.technical_details.indicator_type }})
                    {% if alert.technical_details.confidence_level > 0 %}
                    <br><strong>Niveau de confiance:</strong> {{ alert.technical_details.confidence_level }}%
                    {% endif %}
                </div>
                {% endif %}
                
                {% if alert.mitre_analysis and alert.mitre_analysis.techniques %}
                <div class="mitre-info">
                    <strong>🎯 MITRE ATT&CK:</strong><br>
                    <strong>Techniques:</strong> {{ alert.mitre_analysis.techniques|join(', ') }}<br>
                    {% if alert.mitre_analysis.tactics %}
                    <strong>Tactiques:</strong> {{ alert.mitre_analysis.tactics|join(', ') }}<br>
                    {% endif %}
                    <em>{{ alert.mitre_analysis.analysis }}</em>
                </div>
                {% endif %}
                
                {% if alert.calculated_risk and alert.calculated_risk.calculated_score %}
                <div style="background: #f3e5f5; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 3px solid #9c27b0;">
                    <strong>📈 Évaluation des risques:</strong> 
                    {{ alert.calculated_risk.calculated_score }}/10 
                    ({{ alert.calculated_risk.risk_category }})
                </div>
                {% endif %}
                
                {% if alert.recommended_actions %}
                <div class="recommendations">
                    <strong>💡 Actions Recommandées:</strong>
                    <ul>
                    {% for action in alert.recommended_actions[:4] %}
                        <li>{{ action }}</li>
                    {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            
            {% if detailed_alerts_section.alert_details|length > 10 %}
            <p style="text-align: center; color: #666; font-style: italic;">
                ... et {{ detailed_alerts_section.alert_details|length - 10 }} autre(s) alerte(s)
            </p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if top_threats %}
        <div class="section">
            <h2>⚠️ Principales Menaces Détectées</h2>
            {% for threat in top_threats %}
            <div class="threat">
                <h4>{{ loop.index }}. {{ threat.name }}</h4>
                <p><strong>Score de risque:</strong> {{ threat.risk_score }}/10</p>
                <p><strong>Occurrences:</strong> {{ threat.count }}</p>
                <p>{{ threat.description }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if recommendations %}
        <div class="section">
            <h2>💡 Recommandations</h2>
            {% for recommendation in recommendations %}
            <div class="recommendation">
                {{ loop.index }}. {{ recommendation }}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Rapport généré automatiquement par le système CTI Dashboard</p>
            <p>Pour toute question, contactez l'équipe de sécurité</p>
        </div>
    </div>
</body>
</html>
        """
        
        from jinja2 import Template
        import re
        
        # Fonction pour nettoyer le résumé exécutif (supprimer les références aux menaces)
        def clean_executive_summary(summary):
            # Supprimer les phrases mentionnant les menaces détectées
            cleaned = re.sub(r'[0-9]+ menace\(s\) ont été détectées et ', '', summary)
            cleaned = re.sub(r'Au cours des dernières 24 heures, ', 'Au cours des dernières 24 heures, ', cleaned)
            return cleaned
        
        # Fonction pour nettoyer les descriptions (supprimer les lignes de 'n')
        def clean_description(description):
            # Supprimer les lignes contenant uniquement des 'n'
            lines = description.split('\n')
            cleaned_lines = [line for line in lines if not re.match(r'^n+$', line.strip())]
            return '\n'.join(cleaned_lines).strip()
        
        # Fonction pour traduire les niveaux
        def translate_level(level):
            translations = {
                'critical': 'Critique',
                'high': 'Élevé', 
                'medium': 'Moyen',
                'low': 'Faible'
            }
            return translations.get(level, level.title())
        
        # Fonction pour formater les timestamps
        def format_timestamp(timestamp):
            from datetime import datetime
            try:
                if isinstance(timestamp, str):
                    # Parser le timestamp si c'est une string
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                return dt.strftime('%d/%m/%Y à %H:%M')
            except:
                return str(timestamp)
        
        template = Template(html_template)
        template.globals['clean_executive_summary'] = clean_executive_summary
        template.globals['clean_description'] = clean_description
        template.globals['translate_level'] = translate_level
        template.globals['format_timestamp'] = format_timestamp
        
        html_content = template.render(
            title=report_data['title'],
            period=report_data['period'],
            generated_at=datetime.now().strftime('%d/%m/%Y à %H:%M'),
            report_type=report_data.get('type', 'daily'),
            report_id=report_data['id'],
            executive_summary=report_data['executive_summary'],
            detailed_alerts_section=report_data.get('detailed_alerts_section'),
            top_threats=report_data.get('top_threats', []),
            recommendations=report_data.get('recommendations', [])
        )
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if os.path.exists(html_path):
            logger.info(f"✅ HTML généré: {html_path}")
            return html_path
        else:
            logger.error(f"❌ Fichier HTML non créé: {html_path}")
            return None
            
     except Exception as e:
        logger.error(f"❌ Erreur génération HTML: {e}")
        return None

    def _save_report_metadata(self, report_data: Dict, pdf_path: str, html_path: str):
     try:
        if self.db_connection:
            with self.db_connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO generated_reports (
                        id, title, type, status, pdf_path, html_path, 
                        created_at, key_metrics, executive_summary
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        pdf_path = EXCLUDED.pdf_path,
                        html_path = EXCLUDED.html_path
                """, (
                    report_data['id'],
                    report_data['title'],
                    report_data['type'],
                    'completed' if (pdf_path and html_path) else 'partial',
                    pdf_path,
                    html_path,
                    datetime.now(),
                    json.dumps(report_data.get('key_metrics', {})),
                    report_data.get('executive_summary', '')
                ))
                self.db_connection.commit()
                logger.info(f"✅ Métadonnées sauvegardées: {report_data['id']}")
        else:
            # Sauvegarde locale en JSON si pas de DB
            metadata_file = os.path.join(self.reports_dir, f"{report_data['id']}_metadata.json")
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'report_data': report_data,
                    'pdf_path': pdf_path,
                    'html_path': html_path,
                    'saved_at': datetime.now().isoformat()
                }, f, indent=2, ensure_ascii=False)
            logger.info(f"✅ Métadonnées JSON sauvegardées: {metadata_file}")
            
     except Exception as e:
        logger.error(f"❌ Erreur sauvegarde métadonnées: {e}")

    def get_recent_reports(self, limit: int = 10) -> List[Dict]:
     try:
        if self.db_connection:
            with self.db_connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, title, type, status, created_at, key_metrics
                    FROM generated_reports 
                    ORDER BY created_at DESC 
                    LIMIT %s
                """, (limit,))
                
                reports = []
                for row in cursor.fetchall():
                    reports.append({
                        'id': row[0],
                        'title': row[1],
                        'type': row[2],
                        'status': row[3],
                        'created_at': row[4].isoformat() if row[4] else None,
                        'key_metrics': json.loads(row[5]) if row[5] else {}
                    })
                return reports
        else:
            # Lister les fichiers locaux
            reports = []
            for filename in os.listdir(self.reports_dir):
                if filename.endswith('_metadata.json'):
                    try:
                        with open(os.path.join(self.reports_dir, filename), 'r') as f:
                            metadata = json.load(f)
                            report_data = metadata.get('report_data', {})
                            reports.append({
                                'id': report_data.get('id', filename),
                                'title': report_data.get('title', 'Rapport'),
                                'type': report_data.get('type', 'unknown'),
                                'status': 'completed',
                                'created_at': metadata.get('saved_at'),
                                'key_metrics': report_data.get('key_metrics', {})
                            })
                    except Exception:
                        continue
            
            # Trier par date et limiter
            reports.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            return reports[:limit]
            
     except Exception as e:
        logger.error(f"❌ Erreur get_recent_reports: {e}")
        return []
    
    

    def _sanitize_text(self, text: str) -> str:
      if not text:
        return ""
        
      if not isinstance(text, str):
        text = str(text)
    
    # Remplacer les caractères problématiques pour XML/HTML
      replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&apos;'
    }
    
      for old, new in replacements.items():
        text = text.replace(old, new)
    
      return text.strip()
    
    def _translate_level(self, level: str) -> str:
     translations = {
        'critical': 'Critique',
        'high': 'Élevé', 
        'medium': 'Moyen',
        'low': 'Faible'
    }
     return translations.get(level, level.title())

    def _format_timestamp(self, timestamp: str) -> str:
     try:
        if timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%d/%m/%Y %H:%M')
        return 'N/A'
     except:
        return timestamp or 'N/A'

    def _categorize_risk(self, score: float) -> str:
     if score >= 8:
        return 'Critique'
     elif score >= 6:
        return 'Élevé'
     elif score >= 4:
        return 'Modéré'
     else:
        return 'Faible'


    def _format_metric_name(self, key: str) -> str:
      formatting = {
        'threats_detected': 'Menaces Détectées',
        'alerts_generated': 'Alertes Générées', 
        'iocs_processed': 'IOCs Traités',
        'risk_level': 'Niveau de Risque',
        'total_indicators': 'Indicateurs Totaux',
        'active_alerts': 'Alertes Actives'
    }
      return formatting.get(key, key.replace('_', ' ').title())
   
    def _generate_daily_executive_summary(self, threats_data: Dict, alerts_data: Dict) -> str:
        """Génère le résumé exécutif quotidien"""
        try:
            threats_count = len(threats_data.get('threats', []))
            alerts_count = len(alerts_data.get('alerts', []))
            
            if threats_count == 0 and alerts_count == 0:
                return "Aucune activité malveillante significative détectée au cours des dernières 24 heures. Le niveau de menace reste faible."
            
            summary = f"Au cours des dernières 24 heures, {threats_count} menace(s) ont été détectées "
            summary += f"et {alerts_count} alerte(s) ont été générées. "
            
            if alerts_count > 5:
                summary += "Le niveau d'activité est élevé et nécessite une surveillance accrue."
            elif alerts_count > 2:
                summary += "Le niveau d'activité est modéré."
            else:
                summary += "Le niveau d'activité reste dans les normes."
            
            return summary
            
        except Exception as e:
            logger.error(f"Erreur génération résumé: {e}")
            return "Erreur lors de la génération du résumé exécutif."
    
    def _calculate_daily_risk_level(self, threats_data: Dict, alerts_data: Dict) -> str:
        """Calcule le niveau de risque quotidien"""
        try:
            threats_count = len(threats_data.get('threats', []))
            alerts_count = len(alerts_data.get('alerts', []))
            
            total_activity = threats_count + alerts_count
            
            if total_activity > 10:
                return "Élevé"
            elif total_activity > 5:
                return "Modéré"
            elif total_activity > 0:
                return "Faible"
            else:
                return "Minimal"
                
        except Exception:
            return "Inconnu"

    def _get_top_daily_threats(self, threats_data: Dict) -> List[Dict]:
        """Récupère les top menaces quotidiennes"""
        try:
            threats = threats_data.get('threats', [])
            
            # Mock data si pas de vraies données
            if not threats:
                return [
                    {'name': 'Pas de menace détectée', 'count': 0, 'risk_score': 0}
                ]
            
            # Trier par risk_score si disponible
            sorted_threats = sorted(
                threats, 
                key=lambda x: x.get('risk_score', 0), 
                reverse=True
            )
            
            # Formater pour le rapport
            top_threats = []
            for threat in sorted_threats[:5]:
                top_threats.append({
                    'name': threat.get('value', threat.get('name', 'Menace inconnue')),
                    'count': 1,  # Ou calculer selon vos données
                    'risk_score': threat.get('risk_score', 0)
                })
            
            return top_threats
            
        except Exception as e:
            logger.error(f"Erreur get_top_daily_threats: {e}")
            return [{'name': 'Erreur récupération menaces', 'count': 0, 'risk_score': 0}]

    def _summarize_daily_alerts(self, alerts_data: Dict) -> Dict:
        """Résume les alertes quotidiennes"""
        try:
            alerts = alerts_data.get('alerts', [])
            
            summary = {
                'total': len(alerts),
                'by_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'acknowledged': 0,
                'unacknowledged': 0
            }
            
            for alert in alerts:
                level = alert.get('level', 'medium')
                if level in summary['by_level']:
                    summary['by_level'][level] += 1
                
                if alert.get('acknowledged', False):
                    summary['acknowledged'] += 1
                else:
                    summary['unacknowledged'] += 1
            
            return summary
            
        except Exception as e:
            logger.error(f"Erreur summarize_daily_alerts: {e}")
            return {'total': 0, 'by_level': {}, 'acknowledged': 0, 'unacknowledged': 0}

    def _generate_daily_recommendations(self, threats_data: Dict, alerts_data: Dict) -> List[str]:
        """Génère des recommandations quotidiennes"""
        try:
            recommendations = []
            
            threats_count = len(threats_data.get('threats', []))
            alerts_count = len(alerts_data.get('alerts', []))
            
            if alerts_count > 5:
                recommendations.append("Réviser les règles de détection pour réduire les faux positifs")
                recommendations.append("Renforcer la surveillance des systèmes critiques")
            
            if threats_count > 0:
                recommendations.append("Mettre à jour les signatures de détection")
                recommendations.append("Effectuer une analyse approfondie des IOCs détectés")
            
            if not recommendations:
                recommendations.append("Maintenir la surveillance continue")
                recommendations.append("Réviser les logs de sécurité quotidiens")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Erreur generate_daily_recommendations: {e}")
            return ["Erreur génération recommandations"]

    def download_report(self, report_id: str) -> Optional[str]:
        """✅ TÉLÉCHARGEMENT CORRIGÉ"""
        try:
            logger.info(f"🔄 Téléchargement rapport: {report_id}")
            
            # Vérifier d'abord dans le dossier local
            pdf_filename = f"{report_id}.pdf"
            pdf_path = os.path.join(self.reports_dir, pdf_filename)
            
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                logger.info(f"✅ Fichier trouvé: {pdf_path}")
                return pdf_path
            
            # Chercher en base si disponible
            if self.db_connection:
                try:
                    with self.db_connection.cursor() as cursor:
                        cursor.execute("""
                            SELECT pdf_path FROM generated_reports 
                            WHERE id = %s AND status = 'completed'
                        """, (report_id,))
                        
                        result = cursor.fetchone()
                        if result and result[0]:
                            db_path = result[0]
                            if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
                                return db_path
                except Exception as db_error:
                    logger.warning(f"⚠️ Erreur recherche DB: {db_error}")
            
            logger.warning(f"⚠️ Fichier non trouvé ou vide: {report_id}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Erreur download_report: {e}")
            return None

    # Ajouter les autres méthodes nécessaires...
    # Modifications dans report_generator.py

    def _generate_detailed_alerts_section(self, alerts_data: Dict) -> Dict[str, Any]:
     try:
        alerts = alerts_data.get('alerts', [])
        
        if not alerts:
            return {
                'total_alerts': 0,
                'alert_details': [],
                'risk_analysis': 'Aucune alerte détectée',
                'recommendations': []
            }
        
        detailed_alerts = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        source_distribution = {}
        
        for alert in alerts:
            # Enrichir chaque alerte avec des détails
            alert_detail = self._enrich_alert_details(alert)
            detailed_alerts.append(alert_detail)
            
            # Statistiques
            level = alert.get('level', 'medium')
            if level in severity_counts:
                severity_counts[level] += 1
            
            source = alert.get('source', 'unknown')
            source_distribution[source] = source_distribution.get(source, 0) + 1
        
        # Analyse des risques basée sur les alertes
        risk_analysis = self._analyze_alerts_risk_pattern(detailed_alerts)
        
        # Recommandations spécifiques aux alertes détectées
        recommendations = self._generate_alert_specific_recommendations(detailed_alerts, severity_counts)
        
        return {
            'total_alerts': len(alerts),
            'alert_details': detailed_alerts,
            'severity_distribution': severity_counts,
            'source_distribution': source_distribution,
            'risk_analysis': risk_analysis,
            'recommendations': recommendations,
            'unacknowledged_count': len([a for a in alerts if not a.get('acknowledged', False)])
        }
        
     except Exception as e:
        logger.error(f"Erreur _generate_detailed_alerts_section: {e}")
        return {'total_alerts': 0, 'alert_details': [], 'error': str(e)}

    def _enrich_alert_details(self, alert: Dict) -> Dict[str, Any]:
     try:
        enriched_alert = {
            'id': alert.get('id', 'N/A'),
            'title': alert.get('title', 'Alerte sans titre'),
            'level': alert.get('level', 'medium'),
            'description': alert.get('description', 'Aucune description'),
            'timestamp': alert.get('timestamp', ''),
            'source': alert.get('source', 'unknown'),
            'acknowledged': alert.get('acknowledged', False),
            'detection_method': alert.get('detection_method', 'unknown'),
            
            # Détails techniques enrichis
            'technical_details': self._extract_technical_details(alert),
            
            # Analyse MITRE ATT&CK si disponible
            'mitre_analysis': self._extract_mitre_analysis(alert),
            
            # Détails des IOCs associés
            'ioc_details': self._extract_ioc_details(alert),
            
            # Contexte géographique/temporel
            'context': self._extract_alert_context(alert),
            
            # Niveau de criticité calculé
            'calculated_risk': self._calculate_alert_risk(alert),
            
            # Actions recommandées
            'recommended_actions': self._get_alert_recommended_actions(alert)
        }
        
        return enriched_alert
        
     except Exception as e:
        logger.error(f"Erreur enrichissement alerte {alert.get('id')}: {e}")
        return alert

    def _extract_technical_details(self, alert: Dict) -> Dict[str, Any]:
      indicator_data = alert.get('indicator_data', {})
    
      technical_details = {
        'indicator_type': indicator_data.get('type', 'N/A'),
        'indicator_value': indicator_data.get('value', 'N/A'),
        'confidence_level': indicator_data.get('confidence', 'N/A'),
        'malware_families': indicator_data.get('malware_families', []),
        'tags': indicator_data.get('tags', []),
        'first_seen': indicator_data.get('first_seen', 'N/A'),
        'last_seen': indicator_data.get('last_seen', 'N/A'),
    }
    
    # Ajout de détails réseau si disponibles
      if 'network_details' in indicator_data:
        technical_details['network_info'] = {
            'port': indicator_data['network_details'].get('port'),
            'protocol': indicator_data['network_details'].get('protocol'),
            'service': indicator_data['network_details'].get('service')
        }
    
      return technical_details

    def _extract_mitre_analysis(self, alert: Dict) -> Dict[str, Any]:
      mitre_data = alert.get('mitre_data', {})
    
      if not mitre_data:
        return {'techniques': [], 'tactics': [], 'analysis': 'Aucune corrélation MITRE disponible'}
    
      analysis = {
        'techniques': mitre_data.get('techniques', []),
        'tactics': mitre_data.get('tactics', []),
        'kill_chain_phase': mitre_data.get('kill_chain_phase', 'unknown'),
        'threat_actor_groups': mitre_data.get('threat_groups', []),
        'analysis': self._generate_mitre_narrative(mitre_data)
    }
    
      return analysis

    def _extract_ioc_details(self, alert: Dict) -> Dict[str, Any]:
     indicator_data = alert.get('indicator_data', {})
    
     ioc_details = {
        'primary_ioc': {
            'type': indicator_data.get('type', 'N/A'),
            'value': indicator_data.get('value', 'N/A'),
            'reputation': indicator_data.get('reputation', 'unknown')
        },
        'related_iocs': indicator_data.get('related_indicators', []),
        'enrichment_data': {
            'geolocation': indicator_data.get('geolocation', {}),
            'whois_data': indicator_data.get('whois', {}),
            'dns_data': indicator_data.get('dns_records', {}),
            'file_hashes': indicator_data.get('hashes', {})
        }
    }
    
     return ioc_details

    def _extract_alert_context(self, alert: Dict) -> Dict[str, Any]:
     timestamp = alert.get('timestamp', '')
    
     context = {
        'detection_time': timestamp,
        'time_to_detection': self._calculate_detection_delay(alert),
        'business_impact': self._assess_business_impact(alert),
        'affected_systems': alert.get('affected_systems', []),
        'network_segment': alert.get('network_segment', 'unknown'),
        'user_context': alert.get('user_info', {}),
        'related_alerts': self._find_related_alerts(alert)
    }
    
     return context

    def _calculate_alert_risk(self, alert: Dict) -> Dict[str, Any]:
     level_scores = {'critical': 9, 'high': 7, 'medium': 5, 'low': 3}
     base_score = level_scores.get(alert.get('level', 'medium'), 5)
    
    # Facteurs d'ajustement
     confidence = alert.get('indicator_data', {}).get('confidence', 50)
     confidence_factor = confidence / 100
    
    # Présence de techniques MITRE critiques
     mitre_techniques = alert.get('mitre_data', {}).get('techniques', [])
     critical_techniques = ['T1055', 'T1083', 'T1057', 'T1082']  # Techniques critiques
     mitre_factor = 1.2 if any(tech in critical_techniques for tech in mitre_techniques) else 1.0
    
     final_score = min(base_score * confidence_factor * mitre_factor, 10)
    
     return {
        'calculated_score': round(final_score, 2),
        'risk_category': self._categorize_risk(final_score),
        'factors': {
            'base_level': alert.get('level'),
            'confidence': confidence,
            'mitre_enhancement': mitre_factor > 1.0
        }
    }

    def _get_alert_recommended_actions(self, alert: Dict) -> List[str]:
     actions = []
    
     alert_level = alert.get('level', 'medium')
     ioc_type = alert.get('indicator_data', {}).get('type', '')
     mitre_techniques = alert.get('mitre_data', {}).get('techniques', [])
    
    # Actions basées sur le niveau
     if alert_level == 'critical':
        actions.extend([
            "Isoler immédiatement les systèmes affectés",
            "Déclencher la procédure d'incident critique",
            "Notifier l'équipe de sécurité senior"
        ])
     elif alert_level == 'high':
        actions.extend([
            "Investiguer en priorité",
            "Vérifier l'intégrité des systèmes concernés",
            "Renforcer la surveillance des systèmes critiques"
        ])
    
    # Actions basées sur le type d'IOC
     if ioc_type == 'ip-addr':
        actions.append("Bloquer l'adresse IP sur les équipements de sécurité")
     elif ioc_type == 'domain':
        actions.append("Ajouter le domaine à la liste de blocage DNS")
     elif ioc_type == 'file':
        actions.append("Scanner et supprimer le fichier des systèmes")
    
    # Actions basées sur MITRE ATT&CK
     if 'T1566' in mitre_techniques:  # Phishing
        actions.append("Sensibiliser les utilisateurs aux tentatives de phishing")
     if 'T1055' in mitre_techniques:  # Process Injection
        actions.append("Analyser les processus suspects sur les endpoints")
    
     return actions[:5]  # Limiter à 5 actions

    def _analyze_alerts_risk_pattern(self, alerts: List[Dict]) -> str:
     if not alerts:
        return "Aucune alerte à analyser"
    
    # Analyse des niveaux de sévérité
     critical_alerts = len([a for a in alerts if a.get('level') == 'critical'])
     high_alerts = len([a for a in alerts if a.get('level') == 'high'])
    
    # Analyse des sources
     sources = {}
     for alert in alerts:
        source = alert.get('source', 'unknown')
        sources[source] = sources.get(source, 0) + 1
    
    # Analyse temporelle
     acknowledged_ratio = len([a for a in alerts if a.get('acknowledged', False)]) / len(alerts) * 100
    
    # Construction du narrative d'analyse
     analysis = f"Analyse de {len(alerts)} alerte(s): "
    
     if critical_alerts > 0:
        analysis += f"{critical_alerts} critique(s), "
     if high_alerts > 0:
        analysis += f"{high_alerts} haute(s), "
    
     analysis += f"Taux d'acquittement: {acknowledged_ratio:.1f}%. "
    
    # Source principale
     main_source = max(sources, key=sources.get) if sources else "unknown"
     analysis += f"Source principale: {main_source} ({sources.get(main_source, 0)} alertes). "
    
    # Recommandation basée sur l'analyse
     if critical_alerts > 2:
        analysis += "Niveau de menace élevé détecté - action immédiate requise."
     elif acknowledged_ratio < 50:
        analysis += "Nombreuses alertes non traitées - révision des processus nécessaire."
     else:
        analysis += "Niveau d'activité normal avec traitement approprié des alertes."
    
     return analysis

    def _generate_alert_specific_recommendations(self, alerts: List[Dict], severity_counts: Dict) -> List[str]:
     recommendations = []
    
    # Recommandations basées sur la sévérité
     if severity_counts.get('critical', 0) > 0:
        recommendations.append(
            f"Traiter immédiatement les {severity_counts['critical']} alerte(s) critique(s) détectée(s)"
        )
    
     if severity_counts.get('high', 0) > 5:
        recommendations.append(
            "Niveau élevé d'alertes haute priorité - réviser les seuils de détection"
        )
    
    # Recommandations basées sur les patterns MITRE
     all_techniques = []
     for alert in alerts:
        mitre_data = alert.get('mitre_data', {})
        all_techniques.extend(mitre_data.get('techniques', []))
    
     technique_counts = {}
     for tech in all_techniques:
        technique_counts[tech] = technique_counts.get(tech, 0) + 1
    
     if technique_counts:
        most_common = max(technique_counts, key=technique_counts.get)
        recommendations.append(
            f"Renforcer les défenses contre la technique {most_common} "
            f"(détectée {technique_counts[most_common]} fois)"
        )
    
    # Recommandations sur l'acquittement
     unacknowledged = len([a for a in alerts if not a.get('acknowledged', False)])
     if unacknowledged > len(alerts) * 0.5:
        recommendations.append(
            f"Traiter les {unacknowledged} alertes non acquittées pour améliorer la réactivité"
        )
    
    # Recommandations générales
     if len(alerts) > 10:
        recommendations.append(
            "Volume élevé d'alertes - considérer l'automatisation du triage"
        )
    
     return recommendations[:4]  # Limiter à 4 recommandations