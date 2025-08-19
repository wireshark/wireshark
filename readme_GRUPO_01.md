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



















































## 3. Justificación técnica de la elección  --> Nilson 

* Criterio de Selección

Wireshark es un proyecto altamente activo. Cuenta con un historial constante de commits y actualizaciones, lo que indica mantenimiento continuo y evolución del software. A su vez es una de las herramientas de análisis de red más conocidas y utilizadas en ciberseguridad y redes. Tiene una comunidad amplia y activa tanto en GitHub como en foros especializados, listas de correo y conferencias.

Wireshark utiliza la GNU General Public License (GPL), lo que permite su uso, estudio, modificación y distribución libre, lo cual es clave para entornos educativos y profesionales.

Wireshark es considerado un estándar de facto para el análisis de tráfico de red, ampliamente referenciado en libros, cursos y certificaciones de ciberseguridad (como CEH, OSCP, etc.).

* Métricas

- Estrellas (stars): Más de 6.000, lo que indica un alto interés por parte de la comunidad.

- Commits: Más de 50.000, lo que refleja un desarrollo activo y sostenido a lo largo de los años.

- Releases: Se publican versiones estables de forma regular, mejorando compatibilidad, seguridad y características.

- Issues: Se mantiene una gestión activa de errores y sugerencias, con cientos de issues cerrados y discusiones colaborativas.

* Comparación con alternativas

| Herramienta       | Interfaz gráfica | Actividad reciente | Licencia | Notas relevantes                                      |
|-------------------|------------------|---------------------|----------|-------------------------------------------------------|
| **Wireshark**     | Sí               | Muy alta            | GPL      | Muy completo, estándar en la industria.               |
| **tcpdump**       | No (solo CLI)    | Alta                | BSD      | Potente, pero sin GUI y con curva de aprendizaje.     |
| **NetworkMiner**  | Sí               | Media               | Freeware | Visual y útil para análisis forense, pero limitada.   |
| **Snort**         | No (CLI + reglas)| Alta                | GPL      | Enfocado en detección de intrusiones, no análisis.    |



## 4. Fundamentos y referencias 

1. [Sanders, 2017] Practical Packet Analysis: Using Wireshark to Solve Real-World Network Problems. No Starch Press.

2. [Combs, 2024] Wireshark Documentation. Wireshark Foundation. Disponible en: https://www.wireshark.org/docs/

3. [Scarfone & Mell, 2007] Guide to Intrusion Detection and Prevention Systems (IDPS). NIST Special Publication 800-94.


4. [Wireshark GitHub, 2025] Wireshark Network Protocol Analyzer (Repositorio de GitHub). https://github.com/wireshark/wireshark


# Proyecto de Wireshark

## 5. Buenas prácticas éticas y legales --> Emilio
- Uso responsable y normativas.  
  - Utilizar Wireshark únicamente con fines educativos, de investigación o diagnóstico autorizado.  
  - Respetar la privacidad y la confidencialidad de la información capturada.  
  - Cumplir con las leyes y normativas vigentes relacionadas con la ciberseguridad y el análisis de redes.  
  - Evitar el uso de la herramienta en redes o sistemas sin el consentimiento explícito del propietario.  

---

## 6. Contribuciones del equipo --> Emilio
- Emilio Córdova – Desarrollo del apartado de buenas prácticas éticas y legales. 
