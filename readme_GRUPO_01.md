
# Wireshark
## 1. Resumen  
**Wireshark** es un analizador de protocolos de red *open-source* utilizado para:  
- Capturar y examinar tráfico en tiempo real o desde archivos (`*.pcap`).  
- Desglosar paquetes según protocolos (TCP/IP, HTTP, DNS, etc.).  
- Soporte multiplataforma (Windows, Linux, macOS).  

**Usos principales**:  
✔ Diagnóstico de redes.  
✔ Desarrollo de software.  
✔ **Ciberseguridad** (detección de anomalías, forense).  
## 2. Utilidad en Ciberseguridad  
### **Funcionalidades clave**  
- **Detección de intrusiones**:  
  - Filtros para identificar ataques (DDoS, escaneo de puertos).  
  - Ejemplo: Detección de paquetes malformados (*Michael Collins, "Network Security Through Data Analysis", 2017*).  

- **Análisis forense**:  
  - Reconstrucción de sesiones para investigar brechas.  
  - Integración con herramientas como NetworkMiner (*SANS Institute, 2020*).  

- **Validación de configuraciones**:  
  - Auditoría de protocolos seguros (TLS/SSL) (*Chris Sanders, "Practical Packet Analysis", 2017*).  

### **Repositorio oficial**  
- **Enlace**: [GitHub Wireshark](https://github.com/wireshark/wireshark).  
- **Métricas**:  
  - +4,000 commits/año.  
  - ~800 contribuidores.  
- **Plugins destacados**: Dissectores para malware (e.g., Cobalt Strike).  

### **Justificación técnica de la elección**  
| Criterio          | Detalle                                                                 | Fuente                                                                 |
|-------------------|-------------------------------------------------------------------------|------------------------------------------------------------------------|
| **Cobertura**     | Soporta +2,000 protocolos.                                             | [Wireshark Wiki](https://wiki.wireshark.org/ProtocolReference)         |
| **Integración**   | Compatible con SIEMs (Splunk, Elasticsearch).                          | *IEEE, "Enhancing Threat Detection with Wireshark and ELK Stack", 2021*|
| **Investigación** | Citado en análisis de IoT y forense digital.                           | *Journal of Cybersecurity Research, 2022*                              |