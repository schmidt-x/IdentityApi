-- args passed from setup_db.sh
-- DB_NAME
-- DB_USER
-- DB_PASSWORD

IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE NAME = N'$(DB_NAME)')
BEGIN
	CREATE DATABASE [$(DB_NAME)]
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE NAME = N'$(DB_USER)')
BEGIN
	CREATE LOGIN [$(DB_USER)] WITH PASSWORD = N'$(DB_PASSWORD)', DEFAULT_DATABASE=[master], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF
END
GO

USE [$(DB_NAME)]

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE NAME = N'$(DB_USER)')
BEGIN
	CREATE USER [$(DB_USER)] FOR LOGIN [$(DB_USER)]
	EXEC sp_addrolemember N'db_owner', N'$(DB_USER)'
END
GO