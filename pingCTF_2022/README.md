# pingCTF 2022 Writeup (3rd Place)
## 1) Baby Rev
In this simple reverse engineering challenge, we are given an executable named ```babyrev``` to analyze. Opening it up in Ghidra, we can easily find the red herring function ```checkflag``` and decompile it. The crucial code in the function is:
```
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((((*param_1 == 'p') && (param_1[1] == 'i')) && (param_1[2] == 'n')) &&
     (((param_1[3] == 'g' && (param_1[4] == '{')) && (param_1[0x25] == '}')))) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    for (local_40 = 0; local_40 < 0x20; local_40 = local_40 + 1) {
      acStack56[local_40] = param_1[(long)local_40 + 5];
    }
    for (local_3c = 0; local_3c < 0x99; local_3c = local_3c + 1) {
      if ((*(uint *)(&KEYS + (long)(local_3c % 0xe) * 4) ^ (int)acStack56[local_3c % 0x1f]) * 4 +
          local_3c * 2 != *(int *)(FLAG + (long)local_3c * 4)) {
        uVar2 = 0;
        goto LAB_00101336;
      }
    }
    uVar2 = 1;
  }
  ```

