#!/bin/bash
rm -rf ~/.local/share/Trash/files/*
rm -rf bin/Release/netcoreapp2.0/*
dotnet publish -c Release --self-contained -r ubuntu.16.04-x64
dotnet publish -c Release --self-contained -r win10-x64
dotnet publish -c Release --self-contained -r opensuse-x64
dotnet publish -c Release --self-contained -r osx-x64

cd bin/Release/netcoreapp2.0
tar -cvf Encryptor-ubuntu.16.04-x64 ubuntu.16.04-x64/*
tar -cvf Encryptor-opensuse-x64 opensuse-x64/*
zip -r Encryptor-win10-x64 win10-x64/*
tar -cvf Encryptor-osx-x64 osx-x64/* 
