#!/bin/bash
rm -rf obj/*
rm -rf ~/.local/share/Trash/files/*
rm -rf bin/Release/netcoreapp2.0/*
dotnet publish -c Release --self-contained -r ubuntu.16.04-x64
dotnet publish -c Release --self-contained -r win10-x64
dotnet publish -c Release --self-contained -r opensuse-x64
dotnet publish -c Release --self-contained -r osx-x64

cd bin/Release/netcoreapp2.0
tar -cvf Encryptor-ubuntu.16.04-x64.tar ubuntu.16.04-x64/*
tar -cvf Encryptor-opensuse-x64.tar opensuse-x64/*
zip -r Encryptor-win10-x64.zip win10-x64/*
tar -cvf Encryptor-osx-x64.tar osx-x64/* 
