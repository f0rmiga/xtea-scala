@ECHO OFF

@ECHO Building xtea-scala.jar

IF EXIST xtea-scala.jar DEL xtea-scala.jar

IF EXIST tempbuild RD /S /Q tempbuild
CALL MKDIR tempbuild
CALL ATTRIB +h tempbuild /S /D

CALL scalac -sourcepath src -d tempbuild src\com\xteascala\XTEA.scala

CD tempbuild
(ECHO Class-Path: scala-library.jar & ECHO.) > MANIFEST.MF
jar -cfm ..\xtea-scala.jar MANIFEST.MF com\xteascala\*.*
CD ..

CALL RD /S /Q tempbuild