# IDC4Android

IDC 4 for Android ELF file is different from what we used for windows PE file. For example, GetEntryPointQty() described in Enumerating Exported Functions section of THE IDAPRO BOOK will retrive nothing for an ELF file.


We write these script to verify the useful of these examples and give the alternative scheme if it dose not.

BTW, We show some examples when confronting with obfuscator of android.


#Details
OBFUSCATED_CODE_ANALYSIS
  - Dynamic_Analysis
    - Hiding_Debugger.idc 
    - JNINativeInterface.idc
    - jni.h	
  - Junk
      - Baidu
        - Hide_Baidu_Junk.idc
  - Entry
      - AliCrackme4
        - Entry.idc


# Reference

- THE IDAPRO BOOK
- https://www.hex-rays.com/products/ida/debugger/scriptable.shtml
- https://www.hex-rays.com/products/ida/support/idadoc/162.shtml
