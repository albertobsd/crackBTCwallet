Version 0.1.20210204
- Added an extra tool get_mkey_ckey to extract the ckey and mkey from the wallet.dat file
- Added rmd160 for hash 
- Added some changes to noaesni version
- Added some memory checks for malloc returned values
- Added all the commands to the noaesni version, thanks Liam i hope this changes were useful to you

Version 0.1.20210102
- Added a precalculated value for expected AES Block decrypted.
  This method skip last XOR of CBC, keeping only the ECB part of AES256
  This save some ~2% of CPU in AESni mode  and ~5% on Lagacy mode

Version 0.1.20211228
- Added missing save range in legacy/mixed mode, file is saved in tested32.bin
