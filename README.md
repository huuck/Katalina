# Katalina
Katalina is like Unicorn but for Dalvik bytecode. It provides an environment that can execute Android bytecode one instruction at a time.

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
