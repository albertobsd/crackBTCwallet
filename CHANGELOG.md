Version 0.1.20210102
- Added a precalculated value for expected AES Block decrypted.
  This method skip last XOR of CBC, keeping only the ECB part of AES25
  This save some ~2% of CPU in AESni mode  and ~5% on Lagacy mode

Version 0.1.20211228
- Added missing save range in legacy/mixed mode, file is saved in tested32.bin
