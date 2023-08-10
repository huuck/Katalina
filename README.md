# Katalina
Katalina is like Unicorn but for Dalvik bytecode. It provides an environment that can execute Android bytecode one instruction at a time.

**How to run?**

```python3 main.py -xe classes.dex```

**How it looks like?**

<img width="781" alt="image" src="https://github.com/huuck/Katalina/assets/3353285/5eb16e8e-44c4-4e3f-9cc4-2ed6a7b847ac">



**What works:**
* most instructions
* same-class method invocations
* Static fields/method invocations
* String APIs
* Base64 APIs

**What kinda works:**
* Iterator APIs
* Arrays APIs
* cross-class non static method invocations and fields

**What's broken:**
* MultiDex
* I/O
