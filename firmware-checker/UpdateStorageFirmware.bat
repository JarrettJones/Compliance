@echo off
REM Mock UpdateStorageFirmware.bat for testing purposes
REM This simulates the output of the real UpdateStorageFirmware.exe -list disk command

if "%1"=="-list" if "%2"=="disk" (
    echo UpdateStorageFirmware.exe found. Running command...
    echo [2025-10-31-23:34:14:909, 14744, 16368] Microsoft UpdateStorageFirmware tool: 1.3.0.2
    echo.
    echo [2025-10-31-23:34:14:909, 14744, 16368] Copyright (c) Microsoft Corporation. All rights reserved.
    echo.
    echo [2025-10-31-23:34:14:909, 14744, 16368] 
    echo.
    echo [2025-10-31-23:34:14:913, 14744, 16368] Device # ^| BusType ^| Type ^| SCSIAddress ^| VendorId ProductId                       ^| SerialNumber                               ^| ActiveFW ^| PendingFW
    echo [2025-10-31-23:34:14:913, 14744, 16368] ------------------------------------------------------------------------------------------------------------------------------------------------------
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 1   ^| NVME    ^| SSD  ^| 02 00 00 00 ^| OSNN                                     ^| 3824BID9Q0117I04019O                       ^| 61080A50 ^| NA
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 2   ^| NVME    ^| SSD  ^| 03 00 00 00 ^| OSNN                                     ^| 5124BIDCQ0073I030V2Q                       ^| 61080A50 ^| NA
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 3   ^| NVME    ^| SSD  ^| 06 00 00 00 ^| OSNN                                     ^| 3824BID9Q0117I0401FP                       ^| 61080A50 ^| NA
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 4   ^| NVME    ^| SSD  ^| 00 00 00 00 ^| MZVL6960HFLB-00AMV                       ^| S89HNG0Y500088                             ^| LDBD1M4Q ^| NA
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 5   ^| NVME    ^| SSD  ^| 05 00 00 00 ^| OSNN                                     ^| 3824BID9Q0117I04018S                       ^| 61080A50 ^| NA
    echo [2025-10-31-23:34:14:913, 14744, 16368] Disk 6   ^| NVME    ^| SSD  ^| 04 00 00 00 ^| OSNN                                     ^| 3824BID9Q0117I040196                       ^| 61080A50 ^| NA
) else (
    echo Usage: UpdateStorageFirmware.exe -list disk
    echo This tool lists storage devices and their firmware versions
)