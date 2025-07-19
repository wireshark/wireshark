# Wireshark: resumen y justificación técnica

## Resumen de la utilidad de Wireshark

Wireshark es un analizador de protocolos de red de código abierto ampliamente reconocido por su capacidad para capturar y examinar en profundidad el tráfico de red en tiempo real. Su uso está extendido en ambientes profesionales, académicos y de investigación, permitiendo analizar el flujo de información hasta el nivel más bajo de los paquetes, visualizar la estructura de protocolos, filtrar tráfico específico e identificar anomalías o patrones anómalos en la red [[1]](#1).

Entre sus funciones más relevantes destacan:
- Captura en tiempo real y análisis retrospectivo de paquetes.
- Filtros avanzados para examinar tráfico específico.
- Interpretación de una amplia variedad de protocolos modernos y legacy.
- Exportación de datos y generación de informes para documentación o auditoría.

---

## Justificación técnica y basada en evidencia

Wireshark es considerado una herramienta indispensable para la administración, diagnóstico y auditoría de redes. Los siguientes criterios técnicos, validados por la literatura especializada, lo justifican:

1. **Diagnóstico profundo y resolución de problemas**  
   Wireshark facilita la detección y solución eficiente de fallos de red, errores de configuración, tráfico malicioso y problemas de rendimiento. La captura y análisis visual de los paquetes permite aislar rápidamente la causa raíz de los problemas, aspecto resaltado en diversas publicaciones técnicas y manuales de referencia [[2]](#2), [[3]](#3).

2. **Ciberseguridad y forense digital**  
   Es una herramienta central para el análisis forense de incidentes de seguridad, ya que permite identificar patrones de ataque (por ejemplo, DDoS, sniffing de contraseñas, exfiltración de datos), analizar la comunicación entre sistemas y recolectar evidencia técnica en investigaciones forenses [[4]](#4), [[7]](#7).

3. **Valor académico y científico**  
   Wireshark se emplea para la docencia y experimentación en programas universitarios de redes y ciberseguridad, al permitir a los estudiantes observar el funcionamiento real de los protocolos en distintos escenarios [[2]](#2), [[5]](#5).

4. **Versatilidad y actualización constante**  
   Es un software de código abierto con una comunidad activa que asegura un soporte continuo, inclusión de nuevos protocolos y respuesta ágil ante vulnerabilidades recientes [[1]](#1).

---

## Referencias

1. <a id="1"></a> [Wireshark Official Documentation. Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)  
2. <a id="2"></a> Sanders, L. (2017). *Wireshark Network Analysis (2nd Edition)*. Protocol Analysis Institute.  
3. <a id="3"></a> De Sort, J. (2022). *Monitorización de redes con Wireshark*. Editorial UOC.  
4. <a id="4"></a> Hemdan, E.E., & Mahmoud, M. (2019). "Research on Wireshark tool as a network protocol analyzer". *Journal of Computer Science Applications and Information Technology*.  
5. <a id="5"></a> Felicia, A. (2018). "Review of Wireshark as a packet analysis tool for network traffic forensic investigation". *International Journal of Computer Applications*.  
6. <a id="6"></a> [Stack Overflow: Para qué sirve Wireshark](https://es.stackoverflow.com/questions/92619/para-qu%C3%A9-sirve-wireshark)  
7. <a id="7"></a> Chappell, L., & Combs, G. (2021). *Wireshark 101: Essential Skills for Network Analysis*. Protocol Analysis Institute.

---

**En conclusión:**  
Wireshark es una herramienta de referencia obligada por su capacidad de ofrecer diagnóstico preciso, soporte a la ciberseguridad y enseñanza de redes, situación avalada por la literatura académica y la comunidad técnica mundial.
