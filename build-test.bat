@ECHO OFF

@ECHO Building xtea-test-scala.jar

IF EXIST xtea-test-scala.jar DEL xtea-test-scala.jar

IF EXIST tempbuild RD /S /Q tempbuild
CALL MKDIR tempbuild
CALL ATTRIB +h tempbuild /S /D

CALL scalac -classpath xtea-scala.jar -sourcepath src -d tempbuild src\com\xteascala\Test.scala

CD tempbuild
(ECHO Main-Class: com.xteascala.Test & ECHO Class-Path: scala-library.jar xtea-scala.jar & ECHO.) > MANIFEST.MF
jar -cfm ..\xtea-test-scala.jar MANIFEST.MF com\xteascala\*.*
CD ..

CALL RD /S /Q tempbuild