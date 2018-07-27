#!/bin/bash
rm -rf ~/.local/share/Trash/files/*
dotnet publish -c Release --self-contained -r ubuntu.16.04-x64
dotnet publish -c Release --self-contained -r win10-x64
